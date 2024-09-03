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

#ifndef BUILD_FOR_WINDOWS
#include <netinet/tcp.h>
#endif

#include "nstackx_dfile_config.h"
#include "nstackx_dfile_session.h"
#include "nstackx_dfile_log.h"
#include "nstackx_error.h"
#include "nstackx_dfile.h"
#include "nstackx_socket.h"
#include "nstackx_util.h"
#include "nstackx_dev.h"

#define TAG "nStackXDFile"

/* thread pos io_0, io_1, io_2, send_0, send_1, send_2, recv, mainloop */
BindInfo g_sender8CoreList[DFILE_BIND_TYPE_INDEX_MAX][GSO_TYPE_INDEX_MAX][DFILE_MAX_THREAD_NUM] = {
    {{{0, 0x10}, {0, 0x08}, {0, 0x04}, {0, 0x20}, {0, 0x40}, {0, 0x80}, {0, 0x02}, {0, 0x40}}, /* nogso highspeed */
     {{0, 0x20}, {0, 0x10}, {0, 0x08}, {0, 0x80}, {0, 0xF0}, {0, 0x00}, {0, 0x02}, {0, 0x40}}}, /* gso highspeed */
    {{{0, 0x00}, {0, 0x00}, {0, 0x00}, {0, 0x20}, {0, 0x40}, {0, 0x80}, {0, 0x00}, {0, 0x00}}, /* nogso lowspeed */
     {{0, 0x00}, {0, 0x00}, {0, 0x00}, {0, 0x80}, {0, 0xF0}, {0, 0x00}, {0, 0x00}, {0, 0x00}}}, /* gso lowspeed */
};

BindInfo g_recver8CoreList[DFILE_BIND_TYPE_INDEX_MAX][DFILE_MAX_THREAD_NUM] = {
    {{0, 0x40}, {0, 0x80}, {0, 0xF0}, {0, 0x00}, {0, 0x00}, {0, 0x00}, {0, 0x20}, {0, 0x10}}, /* highspeed */
    {{0, 0x00}, {0, 0x00}, {0, 0x00}, {0, 0x00}, {0, 0x00}, {0, 0x00}, {0, 0x20}, {0, 0x00}}, /* lowspeed */
};

enum {
    NO_CHECK = 0,
    CHECKED_NOT_SUPPORT,
    CHECKED_SUPPORT
};

static uint8_t g_aesInChecked = NO_CHECK;

void SetTidToBindInfo(const DFileSession *session, uint32_t pos)
{
    pid_t tid = gettid();
    int32_t isSupport = (CapsGSO(session) || CapsTcp(session)) ? 1 : 0;
    int i;
    for (i = 0; i < DFILE_BIND_TYPE_INDEX_MAX; i++) {
        if (session->sessionType == DFILE_SESSION_TYPE_CLIENT) {
            g_sender8CoreList[i][isSupport][pos].tid = tid;
        } else {
            g_recver8CoreList[i][pos].tid = tid;
        }
    }
}

static void GetFileConfigP2p(DFileConfig *dFileConfig, uint16_t mtu)
{
    dFileConfig->dataFrameSize = NSTACKX_P2P_FRAME_SIZE_TIMES * mtu;
    if (dFileConfig->dataFrameSize == 0 || dFileConfig->dataFrameSize <
        NSTACKX_P2P_SEND_RATE * DATA_FRAME_SEND_INTERVAL_MS / MSEC_TICKS_PER_SEC /
        (UINT16_MAX - NSTACKX_P2P_COMPENSATION_RATE)) {
        return;
    }
    dFileConfig->sendRate =
        (uint16_t)(NSTACKX_P2P_SEND_RATE / MSEC_TICKS_PER_SEC * DATA_FRAME_SEND_INTERVAL_MS /
        dFileConfig->dataFrameSize + NSTACKX_P2P_COMPENSATION_RATE);
}

static void GetFileConfigWlan(DFileConfig *dFileConfig, uint16_t mtu)
{
    dFileConfig->dataFrameSize = NSTACKX_WLAN_FRAME_SIZE_TIMES * mtu;
    if (dFileConfig->dataFrameSize == 0 || dFileConfig->dataFrameSize <
        NSTACKX_WLAN_SEND_RATE * DATA_FRAME_SEND_INTERVAL_MS / MSEC_TICKS_PER_SEC /
        (UINT16_MAX - NSTACKX_WLAN_COMPENSATION_RATE)) {
        return;
    }
    dFileConfig->sendRate =
    (uint16_t)(NSTACKX_WLAN_SEND_RATE / MSEC_TICKS_PER_SEC * DATA_FRAME_SEND_INTERVAL_MS / dFileConfig->dataFrameSize +
    NSTACKX_WLAN_COMPENSATION_RATE);
}

static int32_t CheckConnType(uint16_t connType)
{
    if ((connType != CONNECT_TYPE_P2P) && (connType != CONNECT_TYPE_WLAN)) {
        return NSTACKX_EINVAL;
    }
    return NSTACKX_EOK;
}

int32_t GetDFileConfig(DFileConfig *dFileConfig, uint16_t mtu, uint16_t connType)
{
    if ((dFileConfig == NULL) || CheckConnType(connType) != NSTACKX_EOK || (mtu == 0)) {
        return NSTACKX_EINVAL;
    }
    if (connType == CONNECT_TYPE_P2P) {
        GetFileConfigP2p(dFileConfig, mtu);
    } else {
        GetFileConfigWlan(dFileConfig, mtu);
    }
    return NSTACKX_EOK;
}

static void ConfigDFileTransP2p(DFileTransConfig *transConfig)
{
    transConfig->maxRtt = NSTACKX_P2P_UDP_RTT;
    transConfig->maxAckCnt = NSTACKX_MAX_ACK_COUNT;
    transConfig->maxCtrlFrameRetryCnt = NSTACKX_P2P_MAX_CONTROL_FRAME_RETRY_COUNT;
    transConfig->maxCtrlFrameTimeout = NSTACKX_P2P_MAX_CONTROL_FRAME_TIMEOUT;
    transConfig->maxFileHeaderConfirmFrameTimeout = NSTACKX_P2P_MAX_FILE_HEADER_CONFIRM_FRAME_TIMEOUT;
    transConfig->maxFileWriteTimeout = NSTACKX_P2P_WRITE_ALL_FILE_DATA_TIMEOUT;
    transConfig->initialRecvIdleTimeout = NSTACKX_P2P_RECEIVER_IDLE_INIT_TIMEOUT;
    transConfig->maxRecvIdleCnt = NSTACKX_P2P_RECEIVER_IDLE_MAX_COUNT;
    transConfig->initialAckInterval = NSTACKX_ACK_INTERVAL;
    transConfig->recvLimitAckInterval = NSTACKX_P2P_RECEIVED_LIMIT_ACK_INTERVAL;
    transConfig->lastFrameAckInterval = NSTACKX_P2P_RECEIVED_LAST_FRAME_ACK_INTERVAL;
    transConfig->maxRetryPageCnt = NSTACKX_P2P_MAX_RETRY_PAGE_COUNT;
    transConfig->maxRetryListNodeCnt = NSTACKX_P2P_MAX_RETRY_LIST_NODE_NUM;
}

static void ConfigDFileTransWlan(DFileTransConfig *transConfig)
{
    transConfig->maxRtt = NSTACKX_WLAN_UDP_RTT;
    transConfig->maxAckCnt = NSTACKX_MAX_ACK_COUNT;
    transConfig->maxCtrlFrameRetryCnt = NSTACKX_WLAN_MAX_CONTROL_FRAME_RETRY_COUNT;
    transConfig->maxCtrlFrameTimeout = NSTACKX_WLAN_MAX_CONTROL_FRAME_TIMEOUT;
    transConfig->maxFileHeaderConfirmFrameTimeout = NSTACKX_WLAN_MAX_FILE_HEADER_CONFIRM_FRAME_TIMEOUT;
    transConfig->maxFileWriteTimeout = NSTACKX_WLAN_WRITE_ALL_FILE_DATA_TIMEOUT;
    transConfig->initialRecvIdleTimeout = NSTACKX_WLAN_RECEIVER_IDLE_INIT_TIMEOUT;
    transConfig->maxRecvIdleCnt = NSTACKX_WLAN_RECEIVER_IDLE_MAX_COUNT;
    transConfig->initialAckInterval = NSTACKX_ACK_INTERVAL;
    transConfig->recvLimitAckInterval = NSTACKX_WLAN_RECEIVED_LIMIT_ACK_INTERVAL;
    transConfig->lastFrameAckInterval = NSTACKX_WLAN_RECEIVED_LAST_FRAME_ACK_INTERVAL;
    transConfig->maxRetryPageCnt = NSTACKX_WLAN_MAX_RETRY_PAGE_COUNT;
    transConfig->maxRetryListNodeCnt = NSTACKX_WLAN_MAX_RETRY_LIST_NODE_NUM;
}

int32_t ConfigDFileTrans(uint16_t connType, DFileTransConfig *transConfig)
{
    if (transConfig == NULL) {
        DFILE_LOGE(TAG, "Invalid parameter");
        return NSTACKX_EINVAL;
    }

    if (CheckConnType(connType) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "Invalid connection type %u", connType);
        return NSTACKX_EINVAL;
    }

    if (connType == CONNECT_TYPE_P2P) {
        ConfigDFileTransP2p(transConfig);
    } else {
        ConfigDFileTransWlan(transConfig);
    }

    return NSTACKX_EOK;
}

void SetTcpKeepAlive(SocketDesc fd)
{
#ifndef BUILD_FOR_WINDOWS
    int32_t optval;

    optval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)(&optval), sizeof(optval)) != 0) {
        DFILE_LOGI(TAG, "set KEEPALIVE failed");
    } else {
        DFILE_LOGI(TAG, "set KEEPALIVE = %d success", optval);
    }

    optval = KEEP_ALIVE_IDLE;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, (void *)(&optval), sizeof(optval)) != 0) {
        DFILE_LOGI(TAG, "set TCP_KEEPIDLE failed");
    } else {
        DFILE_LOGI(TAG, "set TCP_KEEPIDLE = %d success", optval);
    }

    optval = KEEP_ALIVE_CNT;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, (void *)(&optval), sizeof(optval)) != 0) {
        DFILE_LOGI(TAG, "set TCP_KEEPCNT failed");
    } else {
        DFILE_LOGI(TAG, "set TCP_KEEPCNT = %d success", optval);
    }

    optval = KEEP_ALIVE_INTERVAL;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, (void *)(&optval), sizeof(optval)) != 0) {
        DFILE_LOGI(TAG, "set TCP_KEEPINTVL failed");
    } else {
        DFILE_LOGI(TAG, "set TCP_KEEPINTVL = %d success", optval);
    }

    optval = TCP_USER_TIMEOUT_VALUE;
    if (setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, (void *)(&optval), sizeof(optval)) != 0) {
        DFILE_LOGI(TAG, "set TCP_USER_TIMEOUT option error");
    } else {
        DFILE_LOGI(TAG, "set TCP_USER_TIMEOUT option success time:%d", optval);
    }
#endif
}

static bool CheckIsSupportHardwareAesNi(void)
{
    if (g_aesInChecked == NO_CHECK) {
        g_aesInChecked = IsSupportHardwareAesNi() ? CHECKED_SUPPORT : CHECKED_NOT_SUPPORT;
        DFILE_LOGI(TAG, "g_aesInChecked is set as %hhu", g_aesInChecked);
    }
    return g_aesInChecked == CHECKED_SUPPORT;
}

void DFileGetCipherCaps(DFileSession *session, SettingFrame *settingFramePara)
{
    if (CapsChaCha(session) && QueryCipherSupportByName(CHACHA20_POLY1305_NAME)) {
        session->cipherCapability |= NSTACKX_CIPHER_CHACHA;
        DFILE_LOGI(TAG, "local cipher support %s.", CHACHA20_POLY1305_NAME);
    } else {
        session->cipherCapability &= ~NSTACKX_CIPHER_CHACHA;
        DFILE_LOGI(TAG, "local cipher no support %s, CapsChaCha is %hhu.", CHACHA20_POLY1305_NAME, CapsChaCha(session));
    }

    bool ret = CheckIsSupportHardwareAesNi();
    if (ret) {
        session->cipherCapability |= NSTACKX_CIPHER_AES_NI;
    }
    settingFramePara->cipherCapability = session->cipherCapability;
    DFILE_LOGI(TAG, "local cipher AES_NI state is %s", ret ? "true" : "false");
}

void DFileChooseCipherType(SettingFrame *hostSettingFrame, DFileSession *session)
{
    if (session->fileManager->keyLen != CHACHA20_KEY_LENGTH) {
        session->cipherCapability &= ~NSTACKX_CIPHER_CHACHA;
        DFILE_LOGI(TAG, "opposite replies no use chacha cipher");
        return;
    }

    uint8_t isRemoteSupportChacha = ((hostSettingFrame->cipherCapability & NSTACKX_CIPHER_CHACHA) != 0);
    uint8_t isRemoteSupportAesNi = ((hostSettingFrame->cipherCapability & NSTACKX_CIPHER_AES_NI) != 0);
    uint8_t isUseMtp = NSTACKX_FALSE;
#ifdef DFILE_ADAPT_MTP
    isUseMtp = session->useMtpFlag;
#endif
    uint8_t isLocalUseChacha = QueryCipherSupportByName(CHACHA20_POLY1305_NAME) && !isUseMtp;
    bool isLocalSupportAesNi = CheckIsSupportHardwareAesNi();
    if (isRemoteSupportChacha && isLocalUseChacha && !(isRemoteSupportAesNi && isLocalSupportAesNi)) {
        session->cipherCapability |= NSTACKX_CIPHER_CHACHA;
    } else {
        session->cipherCapability &= ~NSTACKX_CIPHER_CHACHA;
    }

    DFILE_LOGI(TAG, "opposite replies %s use chacha cipher", CapsChaCha(session) ? "" : "no");
}