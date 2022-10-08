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

#include "p2plink_adapter.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "p2plink_channel_freq.h"
#include "p2plink_type.h"
#include "securec.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"
#include "wifi_device.h"
#include "wifi_hid2d.h"
#include "wifi_p2p.h"
#include "wifi_p2p_config.h"

#define MAC_BIN_LEN 6
#define FREQ_MAX_LEN 4
#define MAC_HEX 16
#define SSID_INDEX 0
#define BSSID_INDEX 1
#define SHARE_KEY_INDEX 2
#define FREQ_INDEX 3
#define CONNECT_MODE_INDEX 4
#define DEFAULT_NET_MASK "255.255.255.0"

static BroadcastRecvCb g_p2pLinkCallBack = {0};

static void ConvertMacStrToBinary(char *macStr, const char *delimit, uint8_t *binMac, int32_t binMacLen)
{
    char *itemStr = NULL;
    char *saveItemPtr = NULL;
    char *endptr = NULL;
    itemStr = strtok_s(macStr, delimit, &saveItemPtr);
    int32_t i = 0;
    while (itemStr != NULL) {
        if (i == binMacLen) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "mac string over max mac bin len.");
            break;
        }
        binMac[i++] = strtoul(itemStr, &endptr, MAC_HEX);
        itemStr = strtok_s(NULL, delimit, &saveItemPtr);
    }
}

static void ConvertMacBinToStr(char *macStr, int32_t macStrSize, unsigned char macBin[MAC_BIN_LEN])
{
#define MAC_INDEX_ZERO 0
#define MAC_INDEX_ONE 1
#define MAC_INDEX_TWO 2
#define MAC_INDEX_TREE 3
#define MAC_INDEX_FOUR 4
#define MAC_INDEX_FIVE 5
    (void)sprintf_s(macStr, macStrSize, "%02x:%02x:%02x:%02x:%02x:%02x",
        macBin[MAC_INDEX_ZERO],  macBin[MAC_INDEX_ONE], macBin[MAC_INDEX_TWO],
        macBin[MAC_INDEX_TREE], macBin[MAC_INDEX_FOUR], macBin[MAC_INDEX_FIVE]);
}

static void DumpGroupInfo(WifiP2pGroupInfo *groupInfo)
{
    int32_t i;
    char macStr[P2P_MAC_LEN] = {0};

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "group owner %d size %d.",
        groupInfo->isP2pGroupOwner, groupInfo->clientDevicesSize);
    for (i = 0; i < groupInfo->clientDevicesSize; i++) {
        macStr[0] = '\0';
        ConvertMacBinToStr(macStr, sizeof(macStr), groupInfo->clientDevices[i].devAddr);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "mac dev[%d].", i);
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "group interface %s.",
        groupInfo->interface);
}

P2pLinkGroup *P2pLinkRequetGroupInfo(void)
{
    WifiP2pGroupInfo *groupInfo;
    P2pLinkGroup *grp = NULL;
    int32_t grpSize;
    int32_t i;
    int32_t ret;
    char macStr[P2P_MAC_LEN] = {0};

    groupInfo = (WifiP2pGroupInfo*)SoftBusCalloc(sizeof(WifiP2pGroupInfo));
    if (groupInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "malloc groupInfo fail.");
        return NULL;
    }
    ret = GetCurrentGroup(groupInfo);
    if (ret != WIFI_SUCCESS) {
        SoftBusFree(groupInfo);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get current group fail[%d].", ret);
        return NULL;
    }
    DumpGroupInfo(groupInfo);

    grpSize = sizeof(P2pLinkGroup) + groupInfo->clientDevicesSize * sizeof(P2pLinkPeerMacList);
    grp = (P2pLinkGroup*)SoftBusCalloc(grpSize);
    if (grp == NULL) {
        SoftBusFree(groupInfo);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "malloc link group fail.");
        return NULL;
    }

    grp->peerMacNum = groupInfo->clientDevicesSize;
    grp->role = (groupInfo->isP2pGroupOwner == 1) ? ROLE_GO : ROLE_GC;
    for (i = 0; i < grp->peerMacNum; i++) {
        macStr[0] = '\0';
        ConvertMacBinToStr(macStr, sizeof(macStr), groupInfo->clientDevices[i].devAddr);
        ret = strcpy_s(grp->peerMacs + i * sizeof(P2pLinkPeerMacList), sizeof(P2pLinkPeerMacList), macStr);
        if (ret != EOK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "strcpy error.");
        }
    }
    SoftBusFree(groupInfo);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "requet groupInfo ok.");
    return grp;
}

static void InnerP2pStateChangedProc(P2pState state)
{
    bool res = true;

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "recv p2p state change %d.", state);
    if (state == P2P_STATE_CLOSED) {
        res = false;
    } else if (state == P2P_STATE_STARTED) {
        res = true;
    } else {
        return;
    }
    if (g_p2pLinkCallBack.p2pStateChanged != NULL) {
        g_p2pLinkCallBack.p2pStateChanged(res);
    }
}

static void InnerGroupStateChangedProc(void)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "recv group state change");
}

static void InnerConnResultProc(WifiP2pLinkedInfo info)
{
    char mac[P2P_MAC_LEN] = {0};

    ConvertMacBinToStr(mac, sizeof(mac), info.groupOwnerAddress);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "recv conn state change conn %d grp %d",
        info.connectState, info.isP2pGroupOwner);

    if (info.isP2pGroupOwner == 0) {
        if (info.connectState == P2P_CONNECTED) {
            if (g_p2pLinkCallBack.connResult != NULL) {
                g_p2pLinkCallBack.connResult(P2PLINK_CONNECTED);
            }
        } else {
            if (g_p2pLinkCallBack.groupStateChanged != NULL) {
                g_p2pLinkCallBack.groupStateChanged(NULL);
            }
        }
    } else {
        if (g_p2pLinkCallBack.groupStateChanged != NULL) {
            P2pLinkGroup *grp = P2pLinkRequetGroupInfo();
            g_p2pLinkCallBack.groupStateChanged(grp);
            if (grp != NULL) {
                SoftBusFree(grp);
            }
        }
    }
}

static void InnerP2pPeersChangedCallback(WifiP2pDevice* devices, int len)
{
    (void)devices;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "InnerP2pPeersChangedCallback len %d.", len);
}

int32_t P2pLinkAdapterInit(const BroadcastRecvCb *cb)
{
    WifiErrorCode ret;

    if (cb == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2pLinkAdapterInit input para illegal.");
        return SOFTBUS_ERR;
    }

    g_p2pLinkCallBack.p2pStateChanged = cb->p2pStateChanged;
    g_p2pLinkCallBack.groupStateChanged = cb->groupStateChanged;
    g_p2pLinkCallBack.connResult = cb->connResult;
    g_p2pLinkCallBack.wifiCfgChanged = cb->wifiCfgChanged;
    g_p2pLinkCallBack.enterDiscState = cb->enterDiscState;
    ret = RegisterP2pStateChangedCallback(InnerP2pStateChangedProc);
    if (ret != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "reg p2p state fail %d.", ret);
        return SOFTBUS_ERR;
    }
    ret = RegisterP2pPersistentGroupsChangedCallback(InnerGroupStateChangedProc);
    if (ret != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "reg group state fail %d.", ret);
        return SOFTBUS_ERR;
    }
    ret = RegisterP2pConnectionChangedCallback(InnerConnResultProc);
    if (ret != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "reg connect state fail %d.", ret);
        return SOFTBUS_ERR;
    }

    ret = RegisterP2pPeersChangedCallback(InnerP2pPeersChangedCallback);
    if (ret != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "reg peer change fail %d.", ret);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pLink Adapter Init ok.");
    return SOFTBUS_OK;
}

static bool GetMacAddr(const char *ifName, unsigned char *macAddr, int32_t len)
{
    struct ifreq ifr;
    if (memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr)) != EOK ||
        strcpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), ifName) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "init ifreq failed.");
        return false;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "create socket failed.");
        return false;
    }

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ioctl SIOCGIFHWADDR failed.");
        close(fd);
        return false;
    }
    close(fd);
    if (memcpy_s(macAddr, len, ifr.ifr_hwaddr.sa_data, len) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memcpy_s macAddr failed.");
        return false;
    }
    return true;
}

static bool GetIpAddr(const char *ifName, char *ipAddr, int32_t len)
{
    struct ifreq ifr;
    if (memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr)) != EOK ||
        strcpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), ifName) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "init ifreq failed.");
        return false;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "create socket failed.");
        return false;
    }
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ioctl SIOCGIFADDR failed.");
        close(fd);
        return false;
    }
    close(fd);
    struct sockaddr_in *sin = (struct sockaddr_in *)(&ifr.ifr_addr);
    if (inet_ntop(sin->sin_family, &sin->sin_addr, ipAddr, len) == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "inet_ntop ip addr failed.");
        return false;
    }
    return true;
}

int32_t P2pLinkGetP2pIpAddress(char *ip, int32_t len)
{
    WifiP2pGroupInfo* groupInfo;
    char ipAddr[P2P_IP_LEN] = {0};
    WifiErrorCode ret;

    groupInfo = (WifiP2pGroupInfo*)SoftBusCalloc(sizeof(WifiP2pGroupInfo));
    if (groupInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "malloc groupInfo fail.");
        return SOFTBUS_ERR;
    }

    ret = GetCurrentGroup(groupInfo);
    if (ret != WIFI_SUCCESS) {
        SoftBusFree(groupInfo);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2pLinkGetP2pIpAddress GetCurrentGroup fail[%d].", ret);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "interface name %s.", groupInfo->interface);

    if (!GetIpAddr(groupInfo->interface, ipAddr, sizeof(ipAddr))) {
        SoftBusFree(groupInfo);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetIpAddr fail.");
        return SOFTBUS_ERR;
    }
    SoftBusFree(groupInfo);
    ret = strcpy_s(ip, len, ipAddr);
    if (ret != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy fail.");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pLinkGet P2p IpAddress.");
    return SOFTBUS_OK;
}

#define P2P_BASE_INTERFACE "p2p0"
int32_t P2pLinkGetBaseMacAddress(char *mac, int32_t len)
{
    unsigned char macAddr[MAC_BIN_LEN] = {0};

    if (GetMacAddr(P2P_BASE_INTERFACE, macAddr, sizeof(macAddr))) {
        ConvertMacBinToStr(mac, len, macAddr);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "get p2p0 mac.");
        return SOFTBUS_OK;
    }
    if (GetMacAddr("wlan0", macAddr, sizeof(macAddr))) {
        ConvertMacBinToStr(mac, len, macAddr);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "get wlan0 mac.");
        return SOFTBUS_OK;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get p2p base mac fail.");
    return SOFTBUS_ERR;
}


int32_t P2pLinkSharelinkRemoveGroup(void)
{
    WifiErrorCode ret =  Hid2dSharedlinkDecrease();
    if (ret != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, " Hid2dSharedlinkDecrease fail[%d]", ret);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pLinkSharelinkRemoveGroup ok.");
    return SOFTBUS_OK;
}

int32_t P2pLinkSharelinkReuse(void)
{
    WifiErrorCode ret = Hid2dSharedlinkIncrease();
    if (ret != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Hid2dSharedlinkIncrease fail[%d]", ret);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pLinkSharelinkReuse ok.");
    return SOFTBUS_OK;
}


P2pLink5GList *P2pLinkGetChannelListFor5G(void)
{
    int32_t chanList[CHAN_LIST_LEN] = {0};
    int32_t ret = Hid2dGetChannelListFor5G(chanList, CHAN_LIST_LEN);
    if (ret != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get channel 5g list failed, ret = %d", ret);
        return NULL;
    }

    int32_t useCnt = 0;
    for (int32_t i = 0; i < CHAN_LIST_LEN; i++) {
        if (chanList[i] == 0) {
            break;
        }
        useCnt++;
    }

    if (useCnt == 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_WARN, "get channel 5g list, no list");
        return NULL;
    }

    P2pLink5GList *channelList = (P2pLink5GList *)SoftBusCalloc(sizeof(P2pLink5GList) + useCnt * sizeof(int32_t));
    if (channelList == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "calloc fail.");
        return NULL;
    }
    channelList->num = useCnt;
    for (int32_t i = 0; i < useCnt; i++) {
        channelList->chans[i] = chanList[i];
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "channel 5g list %d : %d.", i, chanList[i]);
    }

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "get channel 5g list success.");
    return channelList;
}


int32_t P2pLinkGetFrequency(void)
{
    int32_t ret;
    WifiLinkedInfo wifiInfo;
    (void)memset_s(&wifiInfo, sizeof(WifiLinkedInfo), 0, sizeof(WifiLinkedInfo));
    ret = GetLinkedInfo(&wifiInfo);
    if (ret != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get wifi station freq failed, ret = %d", ret);
        return -1;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "get wifi freq success : %d", wifiInfo.frequency);
    return wifiInfo.frequency;
}

int32_t P2pLinkCreateGroup(int32_t freq, bool isWideBandSupport)
{
    FreqType type = FREQUENCY_DEFAULT;
    if (isWideBandSupport) {
        type = FREQUENCY_160M;
    }
    int32_t ret = Hid2dCreateGroup(freq, type);
    if (ret != WIFI_SUCCESS) {
        return SOFTBUS_ERR;
    }

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "rcreate group end.");
    return SOFTBUS_OK;
}

int32_t P2pLinkGetRecommendChannel(int32_t *freq)
{
    if (freq == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get recommand channel, invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    RecommendChannelRequest request;
    RecommendChannelResponse response;
    int32_t ret = Hid2dGetRecommendChannel(&request, &response);
    if (ret != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get recommand channel failed, ret = %d.", ret);
        return SOFTBUS_ERR;
    }

    if (response.centerFreq != 0) {
        *freq = response.centerFreq;
        return SOFTBUS_OK;
    }

    if (response.centerFreq1 != 0) {
        *freq = response.centerFreq1;
        return SOFTBUS_OK;
    }

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "no suitable 2.4G and 5G recommnad channel.");
    return SOFTBUS_ERR;
}

char *P2pLinkGetGroupConfigInfo(void)
{
    WifiP2pGroupInfo *groupInfo = NULL;
    int32_t ret;
    char macStr[P2P_MAC_LEN] = {0};
    unsigned char macAddr[MAC_BIN_LEN] = {0};

    groupInfo = (WifiP2pGroupInfo *)SoftBusCalloc(sizeof(WifiP2pGroupInfo));
    if (groupInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "calloc groupInfo fail.");
        return NULL;
    }

    ret = GetCurrentGroup(groupInfo);
    if (ret != WIFI_SUCCESS) {
        SoftBusFree(groupInfo);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get current group fail[%d].", ret);
        return NULL;
    }

    if (!GetMacAddr(groupInfo->interface, macAddr, sizeof(macAddr))) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get p2p mac by interface name failed.");
        SoftBusFree(groupInfo);
        return NULL;
    }

    ConvertMacBinToStr(macStr, sizeof(macStr), macAddr);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "p2p interface = %s", groupInfo->interface);
    // 4: \n and \0
    int32_t cfgSize = strlen(groupInfo->groupName) + strlen(macStr) + strlen(groupInfo->passphrase) + FREQ_MAX_LEN + 4;
    char *groupCfgStr = (char *)SoftBusCalloc(cfgSize);

    if (groupCfgStr == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "calloc group config str fail");
        SoftBusFree(groupInfo);
        return NULL;
    }

    ret = sprintf_s(groupCfgStr, cfgSize, "%s\n%s\n%s\n%d", groupInfo->groupName,
        macStr, groupInfo->passphrase, groupInfo->frequency);
    SoftBusFree(groupInfo);
    if (ret == -1) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "sprintf_s group config string failed.");
        SoftBusFree(groupCfgStr);
        return NULL;
    }

    return groupCfgStr;
}

int32_t P2pLinkConnectGroup(const char *groupConfig)
{
    if (groupConfig == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "connect group, invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    char groupCfg[GROUP_CONFIG_LEN] = {0};
    if (strcpy_s(groupCfg, sizeof(groupCfg), groupConfig) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy_s group config string failed.");
        return SOFTBUS_MEM_ERR;
    }

    char *parseList[MAX_GROUP_CONFIG_ITEM_NUM] = {0};
    int32_t outNum;
    int32_t ret;
    P2pLinkParseItemDataByDelimit(groupCfg, "\n", parseList, MAX_GROUP_CONFIG_ITEM_NUM, &outNum);
    if (outNum < GROUP_CONFIG_ITEM_NUM) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "group config string is not enough.");
        return SOFTBUS_MEM_ERR;
    }

    Hid2dConnectConfig config;
    (void)memset_s(&config, sizeof(config), 0, sizeof(config));
    ConvertMacStrToBinary(parseList[BSSID_INDEX], ":", config.bssid, sizeof(config.bssid));
    if (strcpy_s(config.ssid, sizeof(config.ssid), parseList[SSID_INDEX]) != EOK ||
        strcpy_s(config.preSharedKey, sizeof(config.preSharedKey), parseList[SHARE_KEY_INDEX]) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy_s failed.");
        return SOFTBUS_MEM_ERR;
    }

    config.frequency = atoi(parseList[FREQ_INDEX]);
    config.dhcpMode = CONNECT_GO_NODHCP;
    if (outNum == MAX_GROUP_CONFIG_ITEM_NUM && !strcmp(parseList[CONNECT_MODE_INDEX], "1")) {
        config.dhcpMode = CONNECT_AP_DHCP;
    }
    ret = Hid2dConnect(&config);
    if (ret != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "connect group failed, ret = %d.", ret);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t P2pLinkRequestGcIp(const char *mac, char *ip, int32_t len)
{
#define IP_INDEX_ZERO 0
#define IP_INDEX_ONE 1
#define IP_INDEX_TWO 2
#define IP_INDEX_TREE 3
    if (mac == NULL || ip == NULL || len == 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "apply ip, invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    unsigned char p2pBaseMac[MAC_LEN] = {0};
    unsigned int ipAddr[IPV4_ARRAY_LEN] = {0};
    char macClone[P2P_MAC_LEN] = {0};
    if (strcpy_s(macClone, sizeof(macClone), mac) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy_s failed.");
        return SOFTBUS_MEM_ERR;
    }

    ConvertMacStrToBinary(macClone, ":", p2pBaseMac, sizeof(p2pBaseMac));
    int32_t ret = Hid2dRequestGcIp(p2pBaseMac, ipAddr);
    if (ret != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "request ip failed, ret = %d.", ret);
        return SOFTBUS_ERR;
    }

    char ipString[P2P_IP_LEN] = {0};
    ret = sprintf_s(ipString, sizeof(ipString), "%u.%u.%u.%u",
        ipAddr[IP_INDEX_ZERO], ipAddr[IP_INDEX_ONE], ipAddr[IP_INDEX_TWO], ipAddr[IP_INDEX_TREE]);
    if (ret == -1) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "sprintf_s request ip failed, ret = %d.", ret);
        return SOFTBUS_MEM_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pLinkRequestGcIp success");
    if (strcpy_s(ip, len, (char *)ipString) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy_s failed.");
        return SOFTBUS_MEM_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t ConvertIpStringToIntArray(unsigned int dest[IPV4_ARRAY_LEN], const char *src)
{
    int32_t ret = sscanf_s(src, "%u.%u.%u.%u", &dest[0], &dest[1], &dest[2], &dest[3]);
    if (ret == -1) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "sscanf_s failed, src = %s.", src);
        return SOFTBUS_MEM_ERR;
    }

    return SOFTBUS_OK;
}

int32_t P2pLinkConfigGcIp(const char *ip)
{
    if (ip == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "config ip, invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    WifiP2pGroupInfo *groupInfo;
    int32_t ret;

    groupInfo = (WifiP2pGroupInfo *)SoftBusCalloc(sizeof(WifiP2pGroupInfo));
    if (groupInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "calloc groupInfo fail.");
        return SOFTBUS_MEM_ERR;
    }

    ret = GetCurrentGroup(groupInfo);
    if (ret != WIFI_SUCCESS) {
        SoftBusFree(groupInfo);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get current group failed, ret = %d.", ret);
        return SOFTBUS_ERR;
    }

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "config ip, interface = %s.", groupInfo->interface);
    IpAddrInfo addrInfo;
    (void)memset_s(&addrInfo, sizeof(addrInfo), 0, sizeof(addrInfo));
    if (ConvertIpStringToIntArray(addrInfo.ip, ip) != SOFTBUS_OK ||
        ConvertIpStringToIntArray(addrInfo.gateway, ip) != SOFTBUS_OK ||
        ConvertIpStringToIntArray(addrInfo.netmask, DEFAULT_NET_MASK) != SOFTBUS_OK) {
        SoftBusFree(groupInfo);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "convert ipaddr string to int array failed.");
        return SOFTBUS_ERR;
    }
    ret = Hid2dConfigIPAddr(groupInfo->interface, &addrInfo);
    SoftBusFree(groupInfo);

    if (ret != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "config ip failed, ret = %d.", ret);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t P2pLinkGetSelfWifiCfgInfo(char *cfgData, int32_t len)
{
    if (cfgData == NULL || len == 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get self wifi config, invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    char wifiCfg[CFG_DATA_MAX_BYTES] = {0};
    int32_t outLen;
    size_t encodeLen;
    int32_t ret = Hid2dGetSelfWifiCfgInfo(TYPE_OF_GET_SELF_CONFIG, wifiCfg, &outLen);
    if (ret != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get self wifi config failed, ret = %d.", ret);
        return SOFTBUS_ERR;
    }

    ret = SoftBusBase64Encode((unsigned char *)cfgData, len, &encodeLen, (unsigned char *)wifiCfg, outLen);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "softbus encode wifi config data failed, ret = %d.", ret);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t P2pLinkSetPeerWifiCfgInfo(const char *cfgData)
{
    if (cfgData == NULL || strlen(cfgData) == 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_WARN, "peer wifi config data is null.");
        return SOFTBUS_OK;
    }

    int32_t cfgStrLen = strlen(cfgData) + 1;
    size_t useLen;
    int32_t ret;
    char *peerWifiCfg = (char *)SoftBusCalloc(cfgStrLen);
    if (peerWifiCfg == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "calloc peer wifi config data failed.");
        return SOFTBUS_MEM_ERR;
    }

    ret = SoftBusBase64Decode((unsigned char *)peerWifiCfg, cfgStrLen, &useLen,
        (unsigned char *)cfgData, strlen(cfgData));
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "softbus decode peer wifi config data failed, ret = %d.", ret);
        SoftBusFree(peerWifiCfg);
        return SOFTBUS_ERR;
    }

    ret = Hid2dSetPeerWifiCfgInfo(TYPE_OF_SET_PEER_CONFIG, peerWifiCfg, useLen);
    if (ret != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "set peer wifi config data failed, ret = %d.", ret);
        SoftBusFree(peerWifiCfg);
        return SOFTBUS_ERR;
    }

    SoftBusFree(peerWifiCfg);
    return SOFTBUS_OK;
}

bool P2pLinkIsWideBandwidthSupported(void)
{
    if (Hid2dIsWideBandwidthSupported() == 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "don't support wide band.");
        return false;
    }

    return true;
}

int32_t P2pLinkReleaseIPAddr(void)
{
    WifiP2pGroupInfo *groupInfo = NULL;
    int32_t ret;

    groupInfo = (WifiP2pGroupInfo*)SoftBusCalloc(sizeof(WifiP2pGroupInfo));
    if (groupInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "malloc groupInfo fail.");
        return SOFTBUS_ERR;
    }
    ret = GetCurrentGroup(groupInfo);
    if (ret != WIFI_SUCCESS) {
        SoftBusFree(groupInfo);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2pLinkReleaseIPAddr GetCurrentGroup fail[%d].", ret);
        return SOFTBUS_ERR;
    }

    ret = Hid2dReleaseIPAddr(groupInfo->interface);
    if (ret != WIFI_SUCCESS) {
        SoftBusFree(groupInfo);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2pLinkReleaseIPAddr releaseIPAddr fail[%d].", ret);
        return SOFTBUS_ERR;
    }
    SoftBusFree(groupInfo);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pLinkReleaseIPAddr ok.");
    return SOFTBUS_OK;
}

int32_t P2pLinkGetWifiState(void)
{
    int wifiState;

    wifiState = IsWifiActive();
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "wifi state %d", wifiState);
    if (wifiState == WIFI_STA_ACTIVE) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

void P2pLinkStopPeerDiscovery(void)
{
    (void)StopDiscoverDevices();
}

void P2pLinkRemoveGroup(void)
{
    WifiErrorCode ret;

    ret = RemoveGroup();
    if (ret != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "remove group faul [%d].", ret);
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "remove group ok");
    if (g_p2pLinkCallBack.enterDiscState != 0) {
        g_p2pLinkCallBack.enterDiscState();
    }
}

void P2pLinkRemoveGcGroup(void)
{
    WifiP2pGroupInfo* groupInfo = NULL;
    WifiErrorCode ret;

    groupInfo = (WifiP2pGroupInfo*)SoftBusCalloc(sizeof(WifiP2pGroupInfo));
    if (groupInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "malloc groupInfo fail.");
        return;
    }
    ret = GetCurrentGroup(groupInfo);
    if (ret != WIFI_SUCCESS) {
        SoftBusFree(groupInfo);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2pLinkRemoveGcGroup GetCurrentGroup fail[%d].", ret);
        return;
    }

    ret = Hid2dRemoveGcGroup(groupInfo->interface);
    if (ret != WIFI_SUCCESS) {
        SoftBusFree(groupInfo);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2pLinkRemoveGcGroup removeGcGroup fail[%d].", ret);
        return;
    }
    SoftBusFree(groupInfo);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pLinkRemoveGcGroup ok.");
    if (g_p2pLinkCallBack.enterDiscState != 0) {
        g_p2pLinkCallBack.enterDiscState();
    }
}
