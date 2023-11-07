/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "wifi_direct_network_utils.h"
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <ifaddrs.h>

#include "securec.h"
#include "softbus_log_old.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "wifi_direct_types.h"
#include "wifi_direct_ipv4_info.h"
#include "wifi_direct_anonymous.h"

#define LOG_LABEL "[WD] NetUt: "

static int32_t SplitString(char *input, char *splitter, char **outputArray, size_t *outputArraySize)
{
    char *context = NULL;
    char *subString = strtok_s(input, splitter, &context);
    CONN_CHECK_AND_RETURN_RET_LOG(subString != NULL, SOFTBUS_ERR, LOG_LABEL "split failed");

    size_t count = 0;
    do {
        outputArray[count] = subString;
        subString = strtok_s(NULL, splitter, &context);
        count++;
    } while (subString && count < *outputArraySize);

    *outputArraySize = count;
    return SOFTBUS_OK;
}

static int32_t ChannelToFrequency(int32_t channel)
{
    CLOGI(LOG_LABEL "channel=%d", channel);
    if (channel >= CHANNEL_2G_FIRST && channel <= CHANNEL_2G_LAST) {
        return (channel - CHANNEL_2G_FIRST) * FREQUENCY_STEP + FREQUENCY_2G_FIRST;
    } else if (channel >= CHANNEL_5G_FIRST && channel <= CHANNEL_5G_LAST) {
        return (channel - CHANNEL_5G_FIRST) * FREQUENCY_STEP + FREQUENCY_5G_FIRST;
    } else {
        return FREQUENCY_INVALID;
    }
}

static int32_t ChannelListToString(int32_t *channelArray, size_t channelArraySize,
                                   char *channelListString, size_t inSize)
{
    int32_t ret;
    size_t outLen = 0;
    for (size_t i = 0; i < channelArraySize; i++) {
        if (i == 0) {
            ret = sprintf_s(channelListString + outLen, inSize - outLen, "%d", channelArray[i]);
        } else {
            ret = sprintf_s(channelListString + outLen, inSize - outLen, "##%d", channelArray[i]);
        }
        CONN_CHECK_AND_RETURN_RET_LOG(ret > 0, SOFTBUS_ERR, LOG_LABEL "format channel failed");
        outLen += (size_t)ret;
    }

    return SOFTBUS_OK;
}

static int32_t StringToChannelList(char *channelListString, int32_t *channelArray, size_t *channelArraySize)
{
    CONN_CHECK_AND_RETURN_RET_LOG(*channelArraySize <= CHANNEL_ARRAY_NUM_MAX, SOFTBUS_INVALID_PARAM,
                                  LOG_LABEL "size too large");

    if (channelListString == NULL || strlen(channelListString) == 0) {
        *channelArraySize = 0;
        return SOFTBUS_OK;
    }
    char *stringCopy = strdup(channelListString);
    if (stringCopy == NULL) {
        CLOGE(LOG_LABEL "copy string failed");
        *channelArraySize = 0;
        return SOFTBUS_MALLOC_ERR;
    }

    char *channelStrings[CHANNEL_ARRAY_NUM_MAX];
    int32_t ret = SplitString(stringCopy, "##", channelStrings, channelArraySize);
    if (ret != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "split channel failed");
        SoftBusFree(stringCopy);
        return ret;
    }

    char *end = NULL;
    for (size_t i = 0; i < *channelArraySize; i++) {
        channelArray[i] = (int32_t)strtol(channelStrings[i], &end, DECIMAL_BASE);
        if (channelArray[i] < 0) {
            CLOGE(LOG_LABEL "to int failed");
            SoftBusFree(stringCopy);
            return SOFTBUS_ERR;
        }
    }

    SoftBusFree(stringCopy);
    return SOFTBUS_OK;
}

static bool Is2GBand(int32_t frequency)
{
    return frequency >= FREQUENCY_2G_FIRST && frequency <= FREQUENCY_2G_LAST;
}

static bool Is5GBand(int32_t frequency)
{
    return frequency >= FREQUENCY_5G_FIRST && frequency <= FREQUENCY_5G_LAST;
}

static int32_t FrequencyToChannel(int32_t frequency)
{
    if (Is2GBand(frequency)) {
        return (frequency - FREQUENCY_2G_FIRST) / FREQUENCY_STEP + CHANNEL_2G_FIRST;
    } else if (Is5GBand(frequency)) {
        return (frequency - FREQUENCY_5G_FIRST) / FREQUENCY_STEP + CHANNEL_5G_FIRST;
    } else {
        return CHANNEL_INVALID;
    }
}

static bool IsInChannelList(int32_t channel, const int32_t *channelArray, size_t channelNum)
{
    for (size_t i = 0; i < channelNum; i++) {
        if (channel == channelArray[i]) {
            return true;
        }
    }
    return false;
}

static int32_t GetInterfaceIpString(const char *interface, char *ipString, int32_t ipStringSize)
{
    CONN_CHECK_AND_RETURN_RET_LOG(interface, SOFTBUS_INVALID_PARAM, "interface is null");
    CONN_CHECK_AND_RETURN_RET_LOG(ipString, SOFTBUS_INVALID_PARAM, "ipString is null");
    CLOGI(LOG_LABEL "interface=%s", interface);

    int32_t socketFd = socket(AF_INET, SOCK_DGRAM, 0);
    CONN_CHECK_AND_RETURN_RET_LOG(socketFd >= 0, SOFTBUS_ERR, LOG_LABEL "open socket failed");

    struct ifreq request;
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    int32_t ret = strcpy_s(request.ifr_name, sizeof(request.ifr_name), interface);
    if (ret != EOK) {
        CLOGE(LOG_LABEL "copy interface name failed");
        close(socketFd);
        return SOFTBUS_ERR;
    }

    ret = ioctl(socketFd, SIOCGIFADDR, &request);
    close(socketFd);
    CONN_CHECK_AND_RETURN_RET_LOG(ret >= 0, SOFTBUS_ERR, LOG_LABEL "get ifr conf failed ret=%d", ret);

    struct sockaddr_in *sockAddrIn = (struct sockaddr_in *)&request.ifr_addr;
    if (!inet_ntop(sockAddrIn->sin_family, &sockAddrIn->sin_addr, ipString, ipStringSize)) {
        CLOGE(LOG_LABEL "inet_ntop failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t IpAddrToString(uint32_t addr, char *addrString, size_t addrStringSize)
{
    addr = ntohl(addr);
    const char *ret = inet_ntop(AF_INET, &addr, addrString, addrStringSize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret, SOFTBUS_ERR, LOG_LABEL "inet_ntop failed");
    return SOFTBUS_OK;
}

static int32_t IpStringToAddr(const char *addrString, uint32_t *addrArray)
{
    if (inet_pton(AF_INET, addrString, addrArray) == 1) {
        *addrArray = htonl(*addrArray);
        return SOFTBUS_OK;
    }
    CLOGE(LOG_LABEL "inet_pton failed");
    return SOFTBUS_ERR;
}

static int32_t IpStringToIntArray(const char *addrString, uint32_t *addrArray, size_t addrArraySize)
{
    CONN_CHECK_AND_RETURN_RET_LOG(addrString, SOFTBUS_INVALID_PARAM, "addrString is null");
    CONN_CHECK_AND_RETURN_RET_LOG(addrArraySize >= IPV4_ADDR_ARRAY_LEN, SOFTBUS_INVALID_PARAM, "array to small");

    int32_t ret = sscanf_s(addrString, "%u.%u.%u.%u", addrArray, addrArray + 1, addrArray + 2, addrArray + 3);
    CONN_CHECK_AND_RETURN_RET_LOG(ret > 0, SOFTBUS_ERR, LOG_LABEL "scan ip number failed");
    return SOFTBUS_OK;
}

static int32_t MacStringToArray(const char *macString, uint8_t *array, size_t *arraySize)
{
    CONN_CHECK_AND_RETURN_RET_LOG(*arraySize >= MAC_ADDR_ARRAY_SIZE, SOFTBUS_INVALID_PARAM, LOG_LABEL "size too small");
    char *subStrings[MAC_ADDR_ARRAY_SIZE];
    size_t subStringsSize = MAC_ADDR_ARRAY_SIZE;

    char *macStringCopy = strdup(macString);
    CONN_CHECK_AND_RETURN_RET_LOG(macStringCopy, SOFTBUS_ERR, LOG_LABEL "dup mac string failed");
    int32_t ret = SplitString(macStringCopy, ":", subStrings, &subStringsSize);
    if (ret != SOFTBUS_OK) {
        CLOGE("split string failed");
        SoftBusFree(macStringCopy);
        return SOFTBUS_ERR;
    }

    char *end = NULL;
    for (size_t i = 0; i < subStringsSize; i++) {
        ret = (int32_t)strtol(subStrings[i], &end, HEX_BASE);
        if (ret < 0) {
            CLOGE("convert to number failed");
            SoftBusFree(macStringCopy);
            return SOFTBUS_ERR;
        }
        array[i] = (uint8_t)ret;
    }

    SoftBusFree(macStringCopy);
    *arraySize = subStringsSize;
    return SOFTBUS_OK;
}

static int32_t MacArrayToString(const uint8_t *array, size_t arraySize, char *macString, size_t macStringSize)
{
    CONN_CHECK_AND_RETURN_RET_LOG(arraySize >= MAC_ADDR_ARRAY_SIZE, SOFTBUS_INVALID_PARAM, LOG_LABEL "mac len invalid");
    size_t ret = sprintf_s(macString, macStringSize, "%02x:%02x:%02x:%02x:%02x:%02x",
                           array[0], array[1], array[2], array[3], array[4], array[5]);
    CONN_CHECK_AND_RETURN_RET_LOG(ret > 0, SOFTBUS_ERR, LOG_LABEL "format mac failed");
    return SOFTBUS_OK;
}

static int32_t GetLocalIpv4InfoArray(struct WifiDirectIpv4Info *info, size_t *size)
{
    struct ifaddrs *ifAddr = NULL;
    if (getifaddrs(&ifAddr) == -1) {
        CLOGE(LOG_LABEL "getifaddrs failed, errno: %d", errno);
        return SOFTBUS_ERR;
    }

    struct ifaddrs *ifa = NULL;
    size_t count = 0;
    for (ifa = ifAddr; ifa != NULL && count < *size; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET || ifa->ifa_netmask == NULL) {
            continue;
        }

        char addrString[IP_ADDR_STR_LEN];
        struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
        info[count].address = ntohl(addr->sin_addr.s_addr);
        inet_ntop(AF_INET, &addr->sin_addr.s_addr, addrString, sizeof(addrString));

        addr = (struct sockaddr_in *)ifa->ifa_netmask;
        info[count].prefixLength = IP_MASK_MAX - (ffs((int32_t)ntohl(addr->sin_addr.s_addr)) - 1);

        CLOGI(LOG_LABEL "name=%s %s/%hhu", ifa->ifa_name, WifiDirectAnonymizeIp(addrString), info[count].prefixLength);
        count++;
    }

    *size = count;
    freeifaddrs(ifAddr);
    return SOFTBUS_OK;
}

static int32_t GetInterfaceMacAddr(const char *ifName, uint8_t *macAddrArray, size_t *macAddrArraySize)
{
    struct ifreq ifr;
    (void)memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr));

    int32_t ret = strcpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), ifName);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy interface name failed");

    int32_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    CONN_CHECK_AND_RETURN_RET_LOG(fd > 0, SOFTBUS_ERR, LOG_LABEL "open socket failed");

    ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);

    if (ret != 0) {
        CLOGE(LOG_LABEL "ioctl get hw addr failed ret=%d", ret);
        close(fd);
        return SOFTBUS_ERR;
    }

    ret = memcpy_s(macAddrArray, *macAddrArraySize, ifr.ifr_hwaddr.sa_data, MAC_ADDR_ARRAY_SIZE);
    if (ret != EOK) {
        CLOGE(LOG_LABEL "copy mac addr failed");
        return SOFTBUS_ERR;
    }

    *macAddrArraySize = MAC_ADDR_ARRAY_SIZE;
    return SOFTBUS_OK;
}

static struct WifiDirectNetWorkUtils g_networkUtils = {
    .getLocalIpv4InfoArray = GetLocalIpv4InfoArray,
    .channelToFrequency = ChannelToFrequency,
    .frequencyToChannel = FrequencyToChannel,
    .channelListToString = ChannelListToString,
    .stringToChannelList = StringToChannelList,
    .is2GBand = Is2GBand,
    .is5GBand = Is5GBand,
    .isInChannelList = IsInChannelList,
    .getInterfaceIpString = GetInterfaceIpString,
    .ipAddrToString = IpAddrToString,
    .ipStringToAddr = IpStringToAddr,
    .ipStringToIntArray = IpStringToIntArray,
    .splitString = SplitString,
    .macStringToArray = MacStringToArray,
    .macArrayToString = MacArrayToString,
    .getInterfaceMacAddr = GetInterfaceMacAddr,
};

struct WifiDirectNetWorkUtils* GetWifiDirectNetWorkUtils(void)
{
    return &g_networkUtils;
}