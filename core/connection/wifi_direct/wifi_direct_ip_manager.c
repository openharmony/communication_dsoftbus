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

#include "wifi_direct_ip_manager.h"
#include <string.h>
#include "securec.h"
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "utils/wifi_direct_network_utils.h"
#include "utils/wifi_direct_anonymous.h"
#include "wifi_direct_p2p_adapter.h"

#define LOG_LABEL "[WD] IpM: "

#define MAX_STATIC_ARP_COUNT 64

#define HML_WORKING_IP_NET_START 1
#define HML_WORKING_IP_NET_END 255
#define HML_WORKING_IP_NET_PREFIX "172.30."

struct IpEntry {
    struct WifiDirectIpv4Info ipv4;
    ListNode node;
};

/* private method forward declare */
static void GenerateConflictList(struct WifiDirectIpv4Info *localArray, size_t localArraySize,
                                 struct WifiDirectIpv4Info *remoteArray, size_t remoteArraySize, ListNode *list);
static void FreeIpEntry(struct ListNode *list);

/* public interface */
static int32_t ApplyIp(struct WifiDirectIpv4Info *remoteArray, int32_t remoteArraySize,
                       struct WifiDirectIpv4Info *local, struct WifiDirectIpv4Info *remote)
{
    size_t localIpv4ArraySize = INTERFACE_NUM_MAX;
    struct WifiDirectIpv4Info localIpv4Array[INTERFACE_NUM_MAX];
    int32_t ret = GetWifiDirectNetWorkUtils()->getLocalIpv4InfoArray(localIpv4Array, &localIpv4ArraySize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "get local ipv4 array failed");

    ListNode conflictList;
    ListInit(&conflictList);
    GenerateConflictList(localIpv4Array, localIpv4ArraySize, remoteArray, remoteArraySize, &conflictList);

    char ipPrefix[IP_ADDR_STR_LEN] = {0};
    char ipString[IP_ADDR_STR_LEN] = {0};
    struct IpEntry *entry = NULL;

    for (int32_t i = HML_WORKING_IP_NET_START; i < HML_WORKING_IP_NET_END; i++) {
        ret = sprintf_s(ipPrefix, sizeof(ipPrefix), HML_WORKING_IP_NET_PREFIX "%d.", i);
        if (ret < 0) {
            continue;
        }
        bool canUse = true;
        LIST_FOR_EACH_ENTRY(entry, &conflictList, struct IpEntry, node) {
            WifiDirectIpv4ToString(&entry->ipv4, ipString, sizeof(ipString));
            if (!strncmp(ipString, ipPrefix, strlen(ipPrefix))) {
                canUse = false;
            }
        }
        if (canUse) {
            break;
        }
    }
    FreeIpEntry(&conflictList);

    ret = sprintf_s(ipString, sizeof(ipString), "%s1", ipPrefix);
    CONN_CHECK_AND_RETURN_RET_LOG(ret > 0, SOFTBUS_ERR, LOG_LABEL "format server ip failed");
    ret = WifiDirectIpStringToIpv4(ipString, local);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "server ip to ipv4 failed");
    ret = sprintf_s(ipString, sizeof(ipString), "%s2", ipPrefix);
    CONN_CHECK_AND_RETURN_RET_LOG(ret > 0, SOFTBUS_ERR, LOG_LABEL "format client ip failed");
    ret = WifiDirectIpStringToIpv4(ipString, remote);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "client ip to ipv4 failed");

    return SOFTBUS_OK;
}

static int32_t ConfigIp(const char *interface, struct WifiDirectIpv4Info *local, struct WifiDirectIpv4Info *remote,
                        const char *remoteMac)
{
    if (interface[0] == '\0' || remoteMac[0] == '\0') {
        CLOGE(LOG_LABEL "invalid interface %s or remote mac %s", interface, remoteMac);
        return SOFTBUS_ERR;
    }

    if (local->address == 0 || remote->address == 0) {
        CLOGE(LOG_LABEL "invalid ip");
        return SOFTBUS_ERR;
    }

    char localIp[IP_ADDR_STR_LEN] = {0};
    char remoteIp[IP_ADDR_STR_LEN] = {0};
    if (WifiDirectIpv4ToString(local, localIp, sizeof(localIp)) != SOFTBUS_OK ||
        WifiDirectIpv4ToString(remote, remoteIp, sizeof(remoteIp)) != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "ip struct to string failed");
        return SOFTBUS_ERR;
    }

    CLOGD(LOG_LABEL "config ip for %s, localIp=%s remoteIp=%s remoteMac=%s", interface,
          WifiDirectAnonymizeIp(localIp), WifiDirectAnonymizeIp(remoteIp), WifiDirectAnonymizeMac(remoteMac));
    if (!GetWifiDirectP2pAdapter()->addInterfaceMultiIps(interface, localIp, local->prefixLength)) {
        CLOGE(LOG_LABEL "add ip failed");
        return SOFTBUS_ERR;
    }

    if (!GetWifiDirectP2pAdapter()->addInterfaceStaticArp(interface, remoteIp, remoteMac)) {
        CLOGE(LOG_LABEL "add static arp failed");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static void ReleaseIp(const char *interface, struct WifiDirectIpv4Info *local, struct WifiDirectIpv4Info *remote,
                      const char *remoteMac)
{
    char localIp[IP_ADDR_STR_LEN] = {0};
    char remoteIp[IP_ADDR_STR_LEN] = {0};
    if (WifiDirectIpv4ToString(local, localIp, sizeof(localIp)) != SOFTBUS_OK ||
        WifiDirectIpv4ToString(remote, remoteIp, sizeof(remoteIp)) != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "ipv4 struct to string failed");
        return;
    }

    CLOGD(LOG_LABEL "release ip for %s, localIp=%s/%hhu remoteIp=%s remoteMac=%s", interface,
          WifiDirectAnonymizeIp(localIp), local->prefixLength,
          WifiDirectAnonymizeIp(remoteIp), WifiDirectAnonymizeMac(remoteMac));

    if (interface[0] == '\0' || local->address == 0) {
        CLOGE(LOG_LABEL "invalid interface or local ip");
    } else if (!GetWifiDirectP2pAdapter()->deleteInterfaceMultiIps(interface, localIp, local->prefixLength)) {
        CLOGE(LOG_LABEL "delete ip failed");
    }

    if (remoteMac[0] == '\0' || remote->address == 0) {
        CLOGE(LOG_LABEL "invalid remote ip or mac");
    } else if (!GetWifiDirectP2pAdapter()->deleteInterfaceStaticArp(interface, remoteIp, remoteMac)) {
        CLOGE(LOG_LABEL "delete static arp failed");
    }
}

static void ClearAllIps(const char *interface)
{
    char *allStaticArp[MAX_STATIC_ARP_COUNT];
    int32_t size = MAX_STATIC_ARP_COUNT;
    if (GetWifiDirectP2pAdapter()->getInterfaceStaticArp(interface, allStaticArp, &size) != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "get static arp failed");
        return;
    }

    for (int32_t i = 0; i < size; i++) {
        if (allStaticArp[i] == NULL) {
            continue;
        }

        char ip[IP_ADDR_STR_LEN] = "";
        char mac[MAC_ADDR_STR_LEN] = "";
        int ret = sscanf_s(allStaticArp[i], "%s/%s", ip, sizeof(ip), mac, sizeof(mac));
        if (ret < 0) {
            CLOGE(LOG_LABEL "get ip and mac of %s failed", WifiDirectAnonymizeMac(allStaticArp[i]));
        } else {
            GetWifiDirectP2pAdapter()->deleteInterfaceStaticArp(interface, ip, mac);
        }
        SoftBusFree(allStaticArp[i]);
    }

    size_t localIpv4ArraySize = INTERFACE_NUM_MAX;
    struct WifiDirectIpv4Info localIpv4Array[INTERFACE_NUM_MAX] = {{0, 0}};
    int ret = GetWifiDirectNetWorkUtils()->getLocalIpv4InfoArray(localIpv4Array, &localIpv4ArraySize);
    CONN_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, LOG_LABEL "no local ip found");

    for (size_t i = 0; i < localIpv4ArraySize; i++) {
        char localIp[IP_ADDR_STR_LEN] = "";
        (void)WifiDirectIpv4ToString(&localIpv4Array[i], localIp, IP_ADDR_STR_LEN);
        if (strncmp(localIp, HML_WORKING_IP_NET_PREFIX, strlen(HML_WORKING_IP_NET_PREFIX)) == 0) {
            CLOGD(LOG_LABEL "local hml IP = %s", WifiDirectAnonymizeIp(localIp));
            GetWifiDirectP2pAdapter()->deleteInterfaceMultiIps(interface, localIp, localIpv4Array[i].prefixLength);
        }
    }
}

/* private method implement */
static void FreeIpEntry(struct ListNode *list)
{
    struct IpEntry *temp = NULL;
    struct IpEntry *ipEntry = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(ipEntry, temp, list, struct IpEntry, node) {
        ListDelete(&ipEntry->node);
        SoftBusFree(ipEntry);
    }
}

static void AddEntry(ListNode *list, struct WifiDirectIpv4Info *ipv4)
{
    struct IpEntry *ipEntry = SoftBusCalloc(sizeof(*ipEntry));
    CONN_CHECK_AND_RETURN_LOG(ipEntry, LOG_LABEL "malloc ip entry failed");

    ListInit(&ipEntry->node);
    ipEntry->ipv4 = *ipv4;
    ListTailInsert(list, &ipEntry->node);
}

static void GenerateConflictList(struct WifiDirectIpv4Info *localArray, size_t localArraySize,
                                 struct WifiDirectIpv4Info *remoteArray, size_t remoteArraySize, ListNode *list)
{
    char ipString[IP_ADDR_STR_LEN] = {0};
    int32_t prefixLen = strlen(HML_WORKING_IP_NET_PREFIX);

    for (size_t i = 0; i < localArraySize; i++) {
        int32_t ret = WifiDirectIpv4ToString(&localArray[i], ipString, sizeof(ipString));
        if (ret != SOFTBUS_OK) {
            continue;
        }
        if (!strncmp(ipString, HML_WORKING_IP_NET_PREFIX, prefixLen)) {
            CLOGD(LOG_LABEL "add %s", WifiDirectAnonymizeIp(ipString));
            AddEntry(list, &localArray[i]);
        }
    }

    for (size_t i = 0; i < remoteArraySize; i++) {
        int32_t ret = WifiDirectIpv4ToString(&remoteArray[i], ipString, sizeof(ipString));
        if (ret != SOFTBUS_OK) {
            continue;
        }
        if (!strncmp(ipString, HML_WORKING_IP_NET_PREFIX, prefixLen)) {
            CLOGD(LOG_LABEL "add %s", ipString);
            AddEntry(list, &remoteArray[i]);
        }
    }
}

static struct WifiDirectIpManager g_manager = {
    .applyIp = ApplyIp,
    .configIp = ConfigIp,
    .releaseIp = ReleaseIp,
    .cleanAllIps = ClearAllIps,
    .ipList = { &g_manager.ipList, &g_manager.ipList },
};

struct WifiDirectIpManager* GetWifiDirectIpManager(void)
{
    return &g_manager;
}