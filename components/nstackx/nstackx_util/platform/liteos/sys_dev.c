/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "nstackx_dev.h"
#include "nstackx_util.h"
#include "nstackx_error.h"
#include "nstackx_log.h"
#include "securec.h"

#define TAG "nStackXDev"

static int32_t GetConnectionTypeByDevName(const char *devName, uint32_t devNameLen, uint16_t *connectType)
{
    int32_t ret = NSTACKX_EFAILED;
    uint32_t p2pNameLen = (uint32_t)strlen(P2P_DEV_NAME_PRE);
    uint32_t wlanNameLen = (uint32_t)strlen(WLAN_DEV_NAME_PRE);

    if (devNameLen >= p2pNameLen && memcmp(devName, P2P_DEV_NAME_PRE, p2pNameLen) == 0) {
        *connectType = CONNECT_TYPE_P2P;
        ret = NSTACKX_EOK;
        LOGI(TAG, "connType is P2P(%hu)", *connectType);
    } else if (devNameLen >= wlanNameLen && memcmp(devName, WLAN_DEV_NAME_PRE, wlanNameLen) == 0) {
        *connectType = CONNECT_TYPE_WLAN;
        LOGI(TAG, "connType is WLAN(%hu)", *connectType);
        ret = NSTACKX_EOK;
    }
    return ret;
}

static int32_t GetInterfaceInfo(int32_t fd, int32_t option, struct ifreq *interface)
{
    if (interface == NULL) {
        return NSTACKX_EINVAL;
    }
    if (ioctl(fd, SIOCGIFFLAGS, (char*)interface) < 0) {
        LOGE(TAG, "ioctl fail, errno = %d", errno);
        return NSTACKX_EFAILED;
    }
    if (!((uint16_t)interface->ifr_flags & IFF_UP)) {
        LOGE(TAG, "interface is not up");
        return NSTACKX_EINVAL;
    }

    /* get IP of this interface */
    if (ioctl(fd, option, (char*)interface) < 0) {
        LOGE(TAG, "ioctl fail, errno = %d", errno);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

int32_t GetInterfaceIP(int32_t fd, struct ifreq *interface)
{
    return GetInterfaceInfo(fd, SIOCGIFADDR, interface);
}

static int32_t GetInterfaceNetMask(int32_t fd, struct ifreq *interface)
{
    return GetInterfaceInfo(fd, SIOCGIFNETMASK, interface);
}

int32_t GetInterfaceList(struct ifconf *ifc, struct ifreq *buf, uint32_t size)
{
    int32_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return NSTACKX_EFAILED;
    }
    ifc->ifc_len = (int32_t)size;
    ifc->ifc_buf = (char*)buf;
    if (ioctl(fd, SIOCGIFCONF, (char*)ifc) < 0) {
        LOGE(TAG, "ioctl fail, errno = %d", errno);
        CloseSocketInner(fd);
        return NSTACKX_EFAILED;
    }
    return fd;
}

int32_t GetConnectionTypeByDev(const uint32_t sourceIp, uint16_t *connectType)
{
    struct ifreq buf[INTERFACE_MAX];
    struct ifconf ifc;

    uint32_t ethNameLen = (uint32_t)strlen(ETH_DEV_NAME_PRE);
    uint32_t wlanNameLen = (uint32_t)strlen(WLAN_DEV_NAME_PRE);
    int32_t fd = GetInterfaceList(&ifc, buf, sizeof(buf));
    if (fd < 0) {
        LOGE(TAG, "get interfacelist failed");
        return NSTACKX_EFAILED;
    }

    int32_t ifreqLen = (int32_t)sizeof(struct ifreq);
    int32_t interfaceNum = (int32_t)(ifc.ifc_len / ifreqLen);
    for (int32_t i = 0; i < interfaceNum && i < INTERFACE_MAX; i++) {
        LOGI(TAG, "ndevice name: %s", buf[i].ifr_name);
        uint32_t ifrNameLen = (uint32_t)strlen(buf[i].ifr_name);
        if (ifrNameLen < ethNameLen && ifrNameLen < wlanNameLen) {
            continue;
        }

        /* get IP of this interface */
        int32_t state = GetInterfaceIP(fd, &buf[i]);
        if (state == NSTACKX_EFAILED) {
            goto L_ERROR;
        } else if (state == NSTACKX_EINVAL) {
            continue;
        }
        if (sourceIp == ((struct sockaddr_in *)&(buf[i].ifr_addr))->sin_addr.s_addr) {
            if (GetConnectionTypeByDevName(buf[i].ifr_name, ifrNameLen, connectType) == NSTACKX_EOK) {
                break;
            }
        }
    }
    CloseSocketInner(fd);
    return NSTACKX_EOK;
L_ERROR:
    CloseSocketInner(fd);
    LOGE(TAG, "get connect type failed");
    return NSTACKX_EFAILED;
}

static int32_t FindDevByInterfaceIP(int32_t fd, struct ifconf ifc, struct ifreq buf[], uint32_t sourceIP)
{
    int32_t i;
    int32_t ifreqLen = (int32_t)sizeof(struct ifreq);
    int32_t interfaceNum = (int32_t)(ifc.ifc_len / ifreqLen);
    for (i = 0; i < interfaceNum && i < INTERFACE_MAX; i++) {
        /* get IP of this interface */
        int32_t state = GetInterfaceIP(fd, &buf[i]);
        if (state == NSTACKX_EFAILED) {
            return NSTACKX_EFAILED;
        } else if (state == NSTACKX_EINVAL) {
            continue;
        }
        if (sourceIP == ((struct sockaddr_in *)&(buf[i].ifr_addr))->sin_addr.s_addr) {
            return i;
        }
    }
    return NSTACKX_EFAILED;
}

int32_t GetInterfaceNameByIP(uint32_t sourceIP, char *interfaceName, size_t nameLen)
{
    struct ifreq buf[INTERFACE_MAX];
    struct ifconf ifc;
    int32_t devIndex;
    int32_t ret = NSTACKX_EOK;
    int32_t fd = GetInterfaceList(&ifc, buf, sizeof(buf));
    if (fd < 0) {
        LOGE(TAG, "can't GetInterfaceList");
        return NSTACKX_EFAILED;
    }
    devIndex = FindDevByInterfaceIP(fd, ifc, buf, sourceIP);
    CloseSocketInner(fd);
    if (devIndex >= 0) {
        if (strcpy_s(interfaceName, nameLen, buf[devIndex].ifr_name) != EOK) {
            LOGE(TAG, "strcpy failed");
            ret = NSTACKX_EFAILED;
        }
    }
    return ret;
}

static int32_t BindToDeviceInner(int32_t sockfd, const struct ifreq *ifBinding)
{
    struct ifreq ifr;

    if (ifBinding == NULL) {
        LOGE(TAG, "no right interface for binding");
        return NSTACKX_EFAILED;
    }
    if (strncpy_s(ifr.ifr_ifrn.ifrn_name, IFNAMSIZ, ifBinding->ifr_name, strlen(ifBinding->ifr_name)) != EOK) {
        LOGE(TAG, "strncpy fail");
        return NSTACKX_EFAILED;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifr, sizeof(ifr)) < 0) {
        LOGE(TAG, "setsockopt fail, errno = %d", errno);
        return NSTACKX_EFAILED;
    }
    LOGI(TAG, "binding interface %s success", ifBinding->ifr_name);
    return NSTACKX_EOK;
}

/*
 * If localAddr isn't NULL, bind to interface correspond to ip,
 * otherwise, bind to interface which is choosed by strategy.
 */
int32_t BindToDevice(SocketDesc sockfd, const struct sockaddr_in *localAddr)
{
    struct ifreq buf[INTERFACE_MAX];
    struct ifconf ifc;
    struct ifreq *ifBinding = NULL;
    uint32_t ethNameLen = (uint32_t)strlen(ETH_DEV_NAME_PRE);
    uint32_t wlanNameLen = (uint32_t)strlen(WLAN_DEV_NAME_PRE);
    int32_t fd = GetInterfaceList(&ifc, buf, sizeof(buf));
    if (fd < 0) {
        return NSTACKX_EFAILED;
    }
    int32_t ifreqLen = (int32_t)sizeof(struct ifreq);
    int32_t interfaceNum = (int32_t)(ifc.ifc_len / ifreqLen);
    for (int32_t i = 0; i < interfaceNum && i < INTERFACE_MAX; i++) {
        LOGI(TAG, "device name: %s", buf[i].ifr_name);
        if (strlen(buf[i].ifr_name) < ethNameLen && strlen(buf[i].ifr_name) < wlanNameLen) {
            continue;
        }
        /* get IP of this interface */
        int32_t state = GetInterfaceIP(fd, &buf[i]);
        if (state == NSTACKX_EFAILED) {
            goto L_ERROR;
        } else if (state == NSTACKX_EINVAL) {
            continue;
        }
        if (localAddr != NULL) {
            /* find corresponding interface by ip */
            if (localAddr->sin_addr.s_addr == ((struct sockaddr_in *)&(buf[i].ifr_addr))->sin_addr.s_addr) {
                ifBinding = &buf[i];
                break;
            }
        } else {
            /* strategy: ethernet have higher priority */
            if (memcmp(buf[i].ifr_name, ETH_DEV_NAME_PRE, ethNameLen) == 0) {
                ifBinding = &buf[i];
                break;
            } else if (memcmp(buf[i].ifr_name, WLAN_DEV_NAME_PRE, wlanNameLen) == 0) {
                ifBinding = &buf[i];
            }
        }
    }
    CloseSocketInner(fd);
    return BindToDeviceInner(sockfd, ifBinding);
L_ERROR:
    LOGE(TAG, "ioctl fail, errno = %d", errno);
    CloseSocketInner(fd);
    return NSTACKX_EFAILED;
}

int32_t GetIfBroadcastIp(const char *ifName, char *ipString, size_t ipStringLen)
{
    struct ifreq buf[INTERFACE_MAX];
    struct ifconf ifc;
    uint8_t foundIp = NSTACKX_FALSE;

    if (ifName == NULL) {
        return NSTACKX_EFAILED;
    }

    int32_t fd = GetInterfaceList(&ifc, buf, sizeof(buf));
    if (fd < 0) {
        return NSTACKX_EFAILED;
    }

    int32_t ifreqLen = (int32_t)sizeof(struct ifreq);
    int32_t interfaceNum = (int32_t)(ifc.ifc_len / ifreqLen);
    for (int32_t i = 0; i < interfaceNum && i < INTERFACE_MAX; i++) {
        if (strlen(buf[i].ifr_name) < strlen(ifName)) {
            continue;
        }
        if (memcmp(buf[i].ifr_name, ifName, strlen(ifName)) != 0) {
            continue;
        }
        if (GetInterfaceInfo(fd, SIOCGIFBRDADDR, &buf[i]) != NSTACKX_EOK) {
            continue;
        }
        if (buf[i].ifr_addr.sa_family != AF_INET) {
            continue;
        }

        if (inet_ntop(AF_INET, &(((struct sockaddr_in *)&(buf[i].ifr_addr))->sin_addr), ipString,
            (socklen_t)ipStringLen) == NULL) {
            continue;
        }
        foundIp = NSTACKX_TRUE;
        break;
    }
    CloseSocketInner(fd);

    if (!foundIp) {
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

static uint8_t IsValidInterface(const char *interfaceName)
{
    if (interfaceName == NULL) {
        return NSTACKX_FALSE;
    }
    uint32_t targetDevLen = (uint32_t)strlen(P2P_DEV_NAME_PRE);
    if (strlen(interfaceName) >= targetDevLen && memcmp(interfaceName, P2P_DEV_NAME_PRE, targetDevLen) == 0) {
        return NSTACKX_TRUE;
    }
    targetDevLen = (uint32_t)strlen(ETH_DEV_NAME_PRE);
    if (strlen(interfaceName) >= targetDevLen && memcmp(interfaceName, ETH_DEV_NAME_PRE, targetDevLen) == 0) {
        return NSTACKX_TRUE;
    }
    targetDevLen = (uint32_t)strlen(WLAN_DEV_NAME_PRE);
    if (strlen(interfaceName) >= targetDevLen && memcmp(interfaceName, WLAN_DEV_NAME_PRE, targetDevLen) == 0) {
        return NSTACKX_TRUE;
    }
    return NSTACKX_FALSE;
}

int32_t GetTargetInterface(const struct sockaddr_in *dstAddr, struct ifreq *localDev)
{
    struct ifreq buf[INTERFACE_MAX];
    struct ifconf ifc;
    uint32_t localIp;
    uint32_t netMask;
    int32_t fd = GetInterfaceList(&ifc, buf, sizeof(buf));
    if (fd < 0) {
        return NSTACKX_EFAILED;
    }
    int32_t ifreqLen = (int32_t)sizeof(struct ifreq);
    int32_t interfaceNum = (int32_t)(ifc.ifc_len / ifreqLen);
    for (int32_t i = 0; i < interfaceNum && i < INTERFACE_MAX; i++) {
        if (!IsValidInterface(buf[i].ifr_name)) {
            continue;
        }
        /* get IP of this interface */
        int32_t state = GetInterfaceIP(fd, &buf[i]);
        if (state == NSTACKX_EFAILED) {
            goto L_ERROR;
        } else if (state == NSTACKX_EINVAL) {
            continue;
        }
        localIp = ((struct sockaddr_in *)(&buf[i].ifr_addr))->sin_addr.s_addr;
        state = GetInterfaceNetMask(fd, &buf[i]);
        if (state == NSTACKX_EFAILED) {
            goto L_ERROR;
        } else if (state == NSTACKX_EINVAL) {
            continue;
        }
        netMask = ((struct sockaddr_in *)&(buf[i].ifr_netmask))->sin_addr.s_addr;
        /* if localIp and dstIp are in the same LAN, fetch the interface name of thie localIp and return */
        if ((dstAddr->sin_addr.s_addr & netMask) == (localIp & netMask)) {
            if (strncpy_s(localDev->ifr_ifrn.ifrn_name, IFNAMSIZ, buf[i].ifr_name, strlen(buf[i].ifr_name)) != EOK) {
                LOGE(TAG, "ifreq name copy failed");
                goto L_ERROR;
            }
            CloseSocketInner(fd);
            return NSTACKX_EOK;
        }
    }
L_ERROR:
    CloseSocketInner(fd);
    return NSTACKX_EFAILED;
}

void BindToDevInTheSameLan(SocketDesc sockfd, const struct sockaddr_in *sockAddr)
{
    struct ifreq localInterface;
    if (sockfd < 0) {
        return;
    }
    (void)memset_s(&localInterface, sizeof(localInterface), 0, sizeof(localInterface));
    if (GetTargetInterface(sockAddr, &localInterface) != NSTACKX_EOK) {
        LOGE(TAG, "get target interface fail");
        return;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&localInterface, sizeof(localInterface)) < 0) {
        LOGE(TAG, "bind to device fail, errno = %d", errno);
        return;
    }
    LOGI(TAG, "bind to %s successfully", localInterface.ifr_name);
}

int32_t BindToTargetDev(SocketDesc sockfd, const char *targetInterfaceName)
{
    struct ifreq buf[INTERFACE_MAX];
    struct ifconf ifc;
    int32_t ret = NSTACKX_EFAILED;
    int32_t fd = GetInterfaceList(&ifc, buf, sizeof(buf));
    if (fd < 0) {
        return NSTACKX_EFAILED;
    }
    int32_t ifreqLen = (int32_t)sizeof(struct ifreq);
    int32_t interfaceNum = (int32_t)(ifc.ifc_len / ifreqLen);
    for (int32_t i = 0; i < interfaceNum && i < INTERFACE_MAX; i++) {
        /* get IP of this interface */
        int32_t state = GetInterfaceIP(fd, &buf[i]);
        if (state == NSTACKX_EFAILED) {
            break;
        } else if (state == NSTACKX_EINVAL) {
            continue;
        }
        if (strlen(buf[i].ifr_name) == strlen(targetInterfaceName) &&
            strcmp(buf[i].ifr_name, targetInterfaceName) == 0) {
            ret = BindToDeviceInner(sockfd, &buf[i]);
            break;
        }
    }
    CloseSocketInner(fd);
    return ret;
}
