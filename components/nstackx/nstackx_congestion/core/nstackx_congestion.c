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

#include "nstackx_congestion.h"
#include "sys_congestion.h"
#include "nstackx_error.h"
#include "nstackx_log.h"
#include "nstackx_util.h"
#include "nstackx_dev.h"
#include "securec.h"

#define TAG "nStackXCongestion"
#define WIFI_THETA_ACCURACY 1000
#define PACKET_HEAD_BYTES 44
#define MS_NUM_PER_SECOND 1000
#define DATA_FRAME_SEND_INTERVAL_MS 5

#define WIFI_DIFS 34
#define WIFI_SIFS 16
#define WIFI_ACK 32
#define WIFI_RTS 28
#define WIFI_CTS 28
#define WIFI_SLOT 9
#define WIFI_WINDOW 8
#define WIFI_PLCP 5
#define WIFI_COMPENSATE_TIME 30
#define MB_SIZE 1048576

#define MAC_HEAD 14
#define IP_HEAD 20
#define UDP_HEAD 8

#define WIFI_ASSEMBLE_NUM 100
#define WIFI_ASSEMBLE_TIMES 8
#define ENHANCE_P2P_SPEED_NUMRATOR 120
#define ENHANCE_P2P_SPEED_DENOMINATOR 100
#define NSTACKX_LEAST_SENDRATE 3 // 3 packets per 5ms
#define NSTACKX_LEAST_SENDRATE_DMSG 1 // MBps

#define NSTACKX_MAX_CONNECTION_NUM 2

static WifiStationInfo g_txWifiStationInfo[NSTACKX_MAX_CONNECTION_NUM] = {{0}};

WifiStationInfo GetGTxWifiStationInfo(uint8_t socketIndex)
{
    return g_txWifiStationInfo[socketIndex];
}

int32_t CheckWlanNegoRateValid(uint32_t rate)
{
    if (rate == 0 || rate > MAX_WIFI_NEGO_RATE) {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static inline uint32_t GetAssembleNumByBitrate(uint32_t speed)
{
    uint32_t times = speed / WIFI_ASSEMBLE_NUM;  /* Mbps */
    return (times > 1) ? (times * WIFI_ASSEMBLE_TIMES) : WIFI_ASSEMBLE_TIMES;
}

static inline uint16_t GetEnhanceP2pSendRate(uint16_t speed)
{
    uint32_t ret = (uint32_t)(speed * ENHANCE_P2P_SPEED_NUMRATOR / ENHANCE_P2P_SPEED_DENOMINATOR);

    ret = (ret > UINT16_MAX) ? UINT16_MAX : ret;
    return (uint16_t)ret;
}

static inline uint32_t GetProtocolHead(void)
{
    return MAC_HEAD + IP_HEAD + UDP_HEAD;
}

static inline uint32_t GetWifiNonDataPacketConsumeTime(void)
{
    const uint32_t time = WIFI_DIFS + WIFI_SLOT * WIFI_WINDOW + WIFI_RTS + WIFI_SIFS + WIFI_CTS + WIFI_SIFS +
                          WIFI_SIFS + WIFI_ACK + WIFI_PLCP + WIFI_COMPENSATE_TIME;
    return time;
}

static inline uint32_t GetThetaByLinkSpeed(uint32_t speedByte, uint32_t mtu)
{
    uint32_t assembleNum = GetAssembleNumByBitrate(speedByte * BITINBYTE);
    uint32_t effectiveSize = mtu * assembleNum;
    uint32_t allSize = (GetWifiNonDataPacketConsumeTime() * speedByte + (PACKET_HEAD_BYTES + mtu) * assembleNum);
    // WIFI_THETA_ACCURACY, ratio accuracy per thousand
    const uint32_t theta = (WIFI_THETA_ACCURACY * effectiveSize / allSize);
    return theta;
}

static inline uint32_t GetSpeedRx(const WifiStationInfo *txWifiStationInfo, const WifiStationInfo *rxWifiStationInfo)
{
    uint32_t speedRX;
    if (rxWifiStationInfo->rxRate == 0) {
        LOGE(TAG, "rxWifiStationInfo.txRateInfo.rateBitrate == 0");
        speedRX = txWifiStationInfo->txRate / BITINBYTE;
    } else {
        speedRX = rxWifiStationInfo->rxRate / BITINBYTE;
    }
    return speedRX;
}

static int32_t GetWlanConngestSendRate(const WifiStationInfo *txWifiStationInfo,
    const WifiStationInfo *rxWifiStationInfo, uint16_t *sendRateResult, uint32_t mtu)
{
    if (CheckWlanNegoRateValid(rxWifiStationInfo->rxRate) != NSTACKX_EOK) {
        LOGE(TAG, "recv endian tx rate error %u", rxWifiStationInfo->rxRate);
        return NSTACKX_EFAILED;
    }

    uint32_t speedTX = txWifiStationInfo->txRate / BITINBYTE;
    uint32_t speedRX = GetSpeedRx(txWifiStationInfo, rxWifiStationInfo);

    uint32_t thetaTx = GetThetaByLinkSpeed(speedTX, mtu);
    uint32_t thetaRx = GetThetaByLinkSpeed(speedRX, mtu);
    uint32_t sendRateOri =
            (speedTX * thetaTx / WIFI_THETA_ACCURACY * speedRX * thetaRx) / (speedTX * thetaTx + speedRX * thetaRx);

    /* the packet num needed to be sent per 5 ms */
    *sendRateResult = (uint16_t)(sendRateOri * MB_SIZE / (mtu + GetProtocolHead()) *
                        DATA_FRAME_SEND_INTERVAL_MS / MS_NUM_PER_SECOND);
    if (*sendRateResult < NSTACKX_LEAST_SENDRATE) {
        *sendRateResult = NSTACKX_LEAST_SENDRATE;
    }

    return NSTACKX_EOK;
}

static int32_t GetP2pCongestSendRate(const WifiStationInfo *txWifiStationInfo,
    const WifiStationInfo *rxWifiStationInfo, uint16_t *sendRateResult, uint32_t mtu)
{
    const WifiStationInfo *wifiStationInfo = txWifiStationInfo;
    if (txWifiStationInfo->txRate < rxWifiStationInfo->txRate) {
        wifiStationInfo = rxWifiStationInfo;
    }

    uint32_t speedTX = wifiStationInfo->txRate / BITINBYTE;
    uint32_t thetaTx = GetThetaByLinkSpeed(speedTX, mtu);
    uint32_t sendRateOri = speedTX * thetaTx / WIFI_THETA_ACCURACY;

    /* the packet num needed to be sent per 5 ms */
    uint16_t realSendRateResult =
            (uint16_t)(sendRateOri * MB_SIZE / (uint32_t)mtu * DATA_FRAME_SEND_INTERVAL_MS / MS_NUM_PER_SECOND);
    *sendRateResult = GetEnhanceP2pSendRate(realSendRateResult);
    if (*sendRateResult < NSTACKX_LEAST_SENDRATE) {
        *sendRateResult = NSTACKX_LEAST_SENDRATE;
    }

    return NSTACKX_EOK;
}

static inline int32_t CheckMtu(uint32_t mtu)
{
    if (mtu <= MIN_MTU || mtu > MAX_MTU) {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

/* calculate the sendrate for client */
int32_t GetConngestSendRate(WifiStationInfo *rxWifiStationInfo, uint16_t connType, uint32_t mtu,
    uint8_t socketIndex, uint16_t *sendRateResult)
{
    int32_t ret;
    if (CheckMtu(mtu) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }

    if (connType == CONNECT_TYPE_WLAN) {
        ret = GetWlanConngestSendRate(&g_txWifiStationInfo[socketIndex],
                                      rxWifiStationInfo, sendRateResult, mtu);
    } else if (connType == CONNECT_TYPE_P2P) {
        ret = GetP2pCongestSendRate(&g_txWifiStationInfo[socketIndex],
                                    rxWifiStationInfo, sendRateResult, mtu);
    } else {
        return NSTACKX_EFAILED;
    }

    return ret;
}

int32_t CheckDevNameValid(const char *devName)
{
    if (devName == NULL || strlen(devName) == 0 || strlen(devName) > IF_NAMESIZE) {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

/* get wifi info of server endian to send to client endian */
int32_t UpdateWifiStationInfo(const char *devName, WifiStationInfo *txWifiStationInfo, uint8_t socketIndex,
    int *changeStatus)
{
    if (changeStatus != NULL) {
        *changeStatus = 0;
    }

    if (CheckDevNameValid(devName) != NSTACKX_EOK || txWifiStationInfo == NULL) {
        return NSTACKX_EFAILED;
    }

    (void)memset_s(txWifiStationInfo, sizeof(WifiStationInfo), 0, sizeof(WifiStationInfo));
    int32_t ret = GetWifiInfo(devName, txWifiStationInfo);
    if (ret != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    if (txWifiStationInfo->txRate != g_txWifiStationInfo[socketIndex].txRate) {
        LOGI(TAG, "new.txRate %u old.txRate %u", txWifiStationInfo->txRate, g_txWifiStationInfo[socketIndex].txRate);
        if (changeStatus != NULL) {
            *changeStatus = 1;
        }
    }

    return memcpy_s(&g_txWifiStationInfo[socketIndex], sizeof(g_txWifiStationInfo[socketIndex]),
                    txWifiStationInfo, sizeof(WifiStationInfo));
}

/* get wifi info of server endian to send to client endian */
int32_t GetServerWifiStationInfo(const char *devName, WifiStationInfo *wifiStationInfo)
{
    if (CheckDevNameValid(devName) != NSTACKX_EOK || wifiStationInfo == NULL) {
        return NSTACKX_EFAILED;
    }

    return GetWifiInfo(devName, wifiStationInfo);
}

int32_t GetWifiInfoDMsg(const char *devName, WifiStationInfo *wifiStationInfo)
{
    if (CheckDevNameValid(devName) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }

    return GetWifiInfo(devName, wifiStationInfo);
}

static int32_t GetWlanConngestSendRateDMsg(uint32_t speedTX, uint32_t speedRX,
    uint32_t *sendRateResult, uint32_t mtu)
{
    if (CheckWlanNegoRateValid(speedTX) != NSTACKX_EOK || CheckWlanNegoRateValid(speedRX) != NSTACKX_EOK) {
        LOGD(TAG, "wifi tx rate or rx rate invalid, tx=%u, rx=%u", speedTX, speedRX);
        return NSTACKX_EFAILED;
    }

    speedTX = speedTX / BITINBYTE;
    speedRX = speedRX / BITINBYTE;

    uint32_t thetaTx = GetThetaByLinkSpeed(speedTX, mtu);
    uint32_t thetaRx = GetThetaByLinkSpeed(speedRX, mtu);
    // MBps
    *sendRateResult =
            (speedTX * thetaTx / WIFI_THETA_ACCURACY * speedRX * thetaRx) / (speedTX * thetaTx + speedRX * thetaRx);
    if (*sendRateResult < NSTACKX_LEAST_SENDRATE_DMSG) {
        *sendRateResult = NSTACKX_LEAST_SENDRATE_DMSG;
    }

    return NSTACKX_EOK;
}

static int32_t GetP2pCongestSendRateDmsg(uint32_t speedTX, uint32_t speedRX,
    uint32_t *sendRateResult, uint32_t mtu)
{
    if (speedRX > speedTX) {
        speedTX = speedRX;
    }
    speedTX = speedTX / BITINBYTE;
    uint32_t thetaTx = GetThetaByLinkSpeed(speedTX, mtu);
    *sendRateResult = speedTX * thetaTx / WIFI_THETA_ACCURACY;

    if (*sendRateResult < NSTACKX_LEAST_SENDRATE_DMSG) {
        *sendRateResult = NSTACKX_LEAST_SENDRATE_DMSG;
    }

    return NSTACKX_EOK;
}

int32_t GetConngestSendRateDMsg(const char *devName, uint32_t speedTX, uint32_t speedRX,
    uint32_t *sendRateResult, uint32_t mtu)
{
    if (CheckDevNameValid(devName) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }

    if (strstr(devName, "p2p") != NULL) {
        return GetP2pCongestSendRateDmsg(speedTX, speedRX, sendRateResult, mtu);
    } else {
        return GetWlanConngestSendRateDMsg(speedTX, speedRX, sendRateResult, mtu);
    }
}
