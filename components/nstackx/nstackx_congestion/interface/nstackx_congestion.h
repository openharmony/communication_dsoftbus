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

#ifndef NSTACKX_CONGESTION_H
#define NSTACKX_CONGESTION_H

#include "nstackx_common_header.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MIN_MTU 64
#define MAX_MTU 65536
#define BITINBYTE 8

#define MAX_WIFI_NEGO_RATE 2500

typedef struct _WifiRateInfo {
    uint32_t rateBitrate;
    uint32_t rateWidth;
} WifiRateInfo;

typedef struct _WifiStationInfo {
    uint32_t txRate;
    uint32_t rxRate;
    int32_t signal;
    uint32_t freq;
} WifiStationInfo;

/* DFX */
typedef struct _RamInfo {
    uint32_t availableRam;
    uint32_t totalRam;
} RamInfo;

typedef enum {
    ROOT_QUEUE = -1,        /* ROOT queueu */
    HI_QUEUE = 1,           /* QDISC queue 1 WLAN_HI_QUEUE = 0 */
    NORMAL_QUEUE,           /* QDISC queue 2 WLAN_NORMAL_QUEUE */
    TCP_DATA_QUEUE,         /* QDISC queue 3 WLAN_TCP_DATA_QUEUE */
    TCP_ACK_QUEUE,          /* QDISC queue 4 WLAN_TCP_ACK_QUEUE */
    UDP_BK_QUEUE,           /* QDISC queue 5 WLAN_UDP_BK_QUEUE */
    UDP_BE_QUEUE,           /* QDISC queue 6 WLAN_UDP_BE_QUEUE */
    UDP_VI_QUEUE,           /* QDISC queue 7 WLAN_UDP_VI_QUEUE */
    UDP_VO_QUEUE,           /* QDISC queue 8 WLAN_UDP_VO_QUEUE */
    MAX_QUEUE,
} QDISC_PROTOCOL_TYPE;

NSTACKX_EXPORT WifiStationInfo GetGTxWifiStationInfo(uint8_t socketIndex);
NSTACKX_EXPORT int32_t CheckWlanNegoRateValid(uint32_t rate);

/* for JNI */
typedef int32_t (*GetWifiInfoHook)(const char *devName, WifiStationInfo *wifiStationInfo);
NSTACKX_EXPORT int32_t CongestionInitGetWifiHook(GetWifiInfoHook getWifiInfoFromCb);

/* for qdisc */
NSTACKX_EXPORT int32_t GetQdiscLen(const char *devName, int32_t protocol, uint32_t *len);

/* for wifi */
NSTACKX_EXPORT int32_t GetServerWifiStationInfo(const char *devName, WifiStationInfo *wifiStationInfo);
NSTACKX_EXPORT int32_t UpdateWifiStationInfo(const char *devName, WifiStationInfo *txWifiStationInfo,
    uint8_t socketIndex, int *changeStatus);
NSTACKX_EXPORT int32_t GetConngestSendRate(WifiStationInfo *rxWifiStationInfo, uint16_t connType, uint32_t mtu,
    uint8_t socketIndex, uint16_t *sendRateResult);
NSTACKX_EXPORT int32_t GetWifiInfoDMsg(const char *devName, WifiStationInfo *wifiStationInfo);
NSTACKX_EXPORT int32_t GetConngestSendRateDMsg(const char *devName, uint32_t speedTX, uint32_t speedRX,
    uint32_t *sendRateResult, uint32_t mtu);

/* init and clean */
NSTACKX_EXPORT int32_t CongModuleInit(void);
NSTACKX_EXPORT void CongModuleClean(void);

#ifdef __cplusplus
}
#endif

#endif
