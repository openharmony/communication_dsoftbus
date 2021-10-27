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

#include "bus_center_info_key.h"
#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"

#define LNN_MAX_IF_NAME_LEN 256
#define LNN_DELIMITER_OUTSIDE ","
#define LNN_DELIMITER_INSIDE ":"

typedef struct {
    ListNode node;
    LnnNetIfNameType type;
    char ifName[NET_IF_NAME_LEN];
} LnnNetIfNameConfig;

static ListNode *g_netIfNameList = NULL;

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

static int32_t AddNetConfigInfo(LnnNetIfNameType type, const char *netIfName, int32_t netIfNameLen)
{
    if (netIfName == NULL || type < LNN_ETH_TYPE || type >= LNN_MAX_NUM_TYPE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parameters invaild!");
        return SOFTBUS_ERR;
    }
    LnnNetIfNameConfig *info = (LnnNetIfNameConfig *)SoftBusMalloc(sizeof(LnnNetIfNameConfig));
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: malloc LnnNetIfNameConfig");
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&info->node);
    if (strncpy_s(info->ifName, NET_IF_NAME_LEN, netIfName, netIfNameLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy netIfName fail");
        SoftBusFree(info);
        return SOFTBUS_ERR;
    }
    info->type = type;
    ListTailInsert(g_netIfNameList, &info->node);
    return SOFTBUS_OK;
}

static int32_t ParseIfNameConfig(char *buf)
{
    char *outerPtr = NULL;
    char *innerPtr = NULL;
    char *value1 = NULL;
    char *value2 = NULL;
    char *key = strtok_r(buf, LNN_DELIMITER_OUTSIDE, &outerPtr);
    while (key != NULL) {
        value1 = strtok_r(key, LNN_DELIMITER_INSIDE, &innerPtr);
        value2 = strtok_r(NULL, LNN_DELIMITER_INSIDE, &innerPtr);
        if (AddNetConfigInfo(atoi(value1), value2, strlen(value2)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "AddNetConfigInfo fail");
            return SOFTBUS_ERR;
        }
        key = strtok_r(NULL, LNN_DELIMITER_OUTSIDE, &outerPtr);
    }
    return SOFTBUS_OK;
}

static int32_t SetIfNameDefaultVal(void)
{
    if (AddNetConfigInfo(LNN_ETH_TYPE, LNN_IF_NAME_ETH, strlen(LNN_IF_NAME_ETH)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "AddNetConfigInfo fail");
        return SOFTBUS_ERR;
    }
    if (AddNetConfigInfo(LNN_WLAN_TYPE, LNN_IF_NAME_WLAN, strlen(LNN_IF_NAME_WLAN)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "AddNetConfigInfo fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnReadNetConfigList(void)
{
    char netIfName[LNN_MAX_IF_NAME_LEN] = {0};
    g_netIfNameList = (ListNode *)SoftBusMalloc(sizeof(ListNode));
    if (g_netIfNameList == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: malloc g_netIfNameList");
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(g_netIfNameList);
    if (SoftbusGetConfig(SOFTBUS_STR_LNN_NET_IF_NAME,
        (unsigned char*)netIfName, sizeof(netIfName)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get lnn net ifname fail, use default value");
        if (SetIfNameDefaultVal() != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "default value set fail");
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    }
    if (ParseIfNameConfig(netIfName) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ifname str parse fail!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnClearNetConfigList(void)
{
    LnnNetIfNameConfig *item = NULL;
    LnnNetIfNameConfig *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_netIfNameList, LnnNetIfNameConfig, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    return SOFTBUS_OK;
}

int32_t LnnGetAddrTypeByIfName(const char *ifName, int32_t ifNameLen, ConnectionAddrType *type)
{
    if (ifName == NULL || type == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parameters are NULL!");
        return SOFTBUS_ERR;
    }
    if (g_netIfNameList == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "g_netIfNameList is null!");
        return SOFTBUS_ERR;
    }
    LnnNetIfNameConfig *info = NULL;
    LIST_FOR_EACH_ENTRY(info, g_netIfNameList, LnnNetIfNameConfig, node) {
        if (strncmp(ifName, info->ifName, ifNameLen) == 0) {
            if (info->type == LNN_ETH_TYPE) {
                *type = CONNECTION_ADDR_ETH;
            }
            if (info->type == LNN_WLAN_TYPE) {
                *type = CONNECTION_ADDR_WLAN;
            }
            break;
        }
    }
    return SOFTBUS_OK;
}

int32_t LnnGetLocalIp(char *ip, uint32_t len, char *ifName, uint32_t ifNameLen)
{
    if (ip == NULL || ifName == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ip or ifName buffer is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_netIfNameList == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "g_netIfNameList is null!");
        return SOFTBUS_ERR;
    }
    int32_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "open socket failed");
        return SOFTBUS_ERR;
    }
    struct ifreq ifr;
    LnnNetIfNameConfig *info = NULL;
    int32_t ret = SOFTBUS_ERR;
    LIST_FOR_EACH_ENTRY(info, g_netIfNameList, LnnNetIfNameConfig, node) {
        if (strncpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), info->ifName, strlen(info->ifName)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy netIfName:%s fail", info->ifName);
            continue;
        }
        if (GetNetworkIfIp(fd, &ifr, ip, len) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNetworkIfIp ifName:%s fail", info->ifName);
            continue;
        }
        if (strncpy_s(ifName, ifNameLen, ifr.ifr_name, strlen(ifr.ifr_name)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy ifname:%s failed", info->ifName);
            continue;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "GetNetworkIfIp ifName:%s ok!", info->ifName);
        ret = SOFTBUS_OK;
        break;
    }
    close(fd);
    return ret;
}
