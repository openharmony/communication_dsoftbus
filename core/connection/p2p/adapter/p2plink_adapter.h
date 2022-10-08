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

#ifndef P2PLINK_ADAPTER_H
#define P2PLINK_ADAPTER_H

#include <stdbool.h>
#include <stdint.h>

#include "p2plink_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    char mac[P2P_MAC_LEN];
} P2pLinkPeerMacList;

typedef struct {
    P2pLinkRole role;
    int32_t peerMacNum;
    char peerMacs[0];
} P2pLinkGroup;

typedef struct {
    int32_t num;
    int32_t chans[0];
} P2pLink5GList;

typedef enum {
    P2PLINK_CONNECTING,
    P2PLINK_CONNECTED,
    P2PLINK_CONNECT_FAILED,
} P2pLinkConnState;

typedef struct  {
    void (*p2pStateChanged)(bool state);
    void (*groupStateChanged)(const P2pLinkGroup *group);
    void (*connResult)(P2pLinkConnState state);
    void (*wifiCfgChanged)(const char *cfgData);
    void (*enterDiscState)(void);
} BroadcastRecvCb;

int32_t P2pLinkAdapterInit(const BroadcastRecvCb *cb);
int32_t P2pLinkGetP2pIpAddress(char *ip, int32_t len);
int32_t P2pLinkGetBaseMacAddress(char *mac, int32_t len);
int32_t P2pLinkCreateGroup(int32_t freq, bool isWideBandSupport);
int32_t P2pLinkGetRecommendChannel(int32_t *freq);
int32_t P2pLinkConnectGroup(const char *groupConfig);
int32_t P2pLinkRequestGcIp(const char* mac, char *ip, int32_t len);
int32_t P2pLinkConfigGcIp(const char *ip);
int32_t P2pLinkGetSelfWifiCfgInfo(char *cfgData, int32_t len);
int32_t P2pLinkSetPeerWifiCfgInfo(const char *cfgData);
int32_t P2pLinkSharelinkReuse(void);
int32_t P2pLinkSharelinkRemoveGroup(void);
int32_t P2pLinkGetWifiState(void);
int32_t P2pLinkReleaseIPAddr(void);
int32_t P2pLinkGetFrequency(void);

P2pLinkGroup *P2pLinkRequetGroupInfo(void);
P2pLink5GList *P2pLinkGetChannelListFor5G(void);

char *P2pLinkGetGroupConfigInfo(void);
bool P2pLinkIsWideBandwidthSupported(void);

void P2pLinkStopPeerDiscovery(void);
void P2pLinkRemoveGroup(void);
void P2pLinkRemoveGcGroup(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* P2PLINK_ADAPTER_H */
