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

#ifndef NSTACKX_DFILE_CONFIG_H
#define NSTACKX_DFILE_CONFIG_H

#include <stdint.h>

#include "nstackx_config.h"
#include "nstackx_util.h"
#include "nstackx_dfile_frame.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 * Enable(1) or Disable(0) fillp support in nStackx Dmsg
 */

/* for struct */
typedef struct DFileConfig {
    uint16_t dataFrameSize;
    uint16_t sendRate;
} DFileConfig;

typedef struct DFileTransConfig {
    uint8_t maxAckCnt; /* Sender wait for number of "maxAckCnt" ACK before timeout */
    uint8_t maxCtrlFrameRetryCnt; /* Max retry count for control frame */
    uint8_t maxRecvIdleCnt; /* Max successive idle count before receiver timeout */
    uint32_t maxRtt;
    uint32_t maxCtrlFrameTimeout; /* Max timeout value for control frame */
    uint32_t maxFileHeaderConfirmFrameTimeout; /* Max timeout value for wait file header confirm frame */
    uint32_t maxFileWriteTimeout; /* Max timeout value for writing all file data */
    uint32_t initialRecvIdleTimeout; /* Initial idle timeout value for receiver */
    uint32_t initialAckInterval; /* Initial ACK interval during normal stage */
    uint32_t recvLimitAckInterval; /* Adjusted ACK interval after receiving 90% frames */
    uint32_t lastFrameAckInterval; /* Adjusted ACK interval after receiving last frame of last file */
    uint32_t maxRetryPageCnt; /* Max number of ACK packets containing retry units per interval */
    uint32_t maxRetryListNodeCnt; /* Max number of retry nodes (retry unit) during transfer. */
} DFileTransConfig;

#define DFILE_MEGABYTES 1048576
#define DFILE_KILOBYTES 1024
#define DATA_FRAME_SEND_INTERVAL_MS 5
#define MSEC_TICKS_PER_SEC 1000
#define USEC_TICKS_PER_MSEC 1000
#define DATA_FRAME_SEND_INTERVAL_US        (USEC_TICKS_PER_MSEC * DATA_FRAME_SEND_INTERVAL_MS)
#define NSTACKX_INIT_ACK_COUNT 50
#define NSTACKX_INIT_ACK_INTERVAL 50
#define NSTACKX_INIT_RATE_STAT_INTERVAL 50000
#define NSTACKX_ACK_INTERVAL 200
#define NSTACKX_RATE_STAT_INTERVAL 200000
#define NSTACKX_CONTROL_INTERVAL 200000
#define NSTACKX_CONGESTION_CONTROL_TIMES  5
#define NSTACKX_MAX_CONTROL_TIMES   10
#define NSTACKX_MIN_SENDRATE 3

#define NSTACKX_MAX_ACK_COUNT 50
#define NSTACKX_DROP_ACK_FIRST_LEVEL 3
#define NSTACKX_DROP_ACK_SECOND_LEVEL 8
#define NSTACKX_DROP_ACK_DIVIDE 15

#define NSTACKX_SEND_ACK_PER_THREE_RECYCLE 5
#define NSTACKX_SEND_ACK_PER_TWO_RECYCLE 2
#define NSTACKX_SEND_ACK_PER_ONE_RECYCLE 1
#define NSTACKX_DIVISION_COMPENSATION_RATE 3
#define NSTACKX_MAX_CLIENT_SEND_THREAD_NUM 3
/* 01 single path 02 multi path */
#define NSTACKX_DFILE_VERSION 0x01

/* for P2P */
/* DFile session configuration */
#define NSTACKX_P2P_SEND_RATE (210 * 1024 * 1024)
#define NSTACKX_P2P_COMPENSATION_RATE 1
#define NSTACKX_P2P_FRAME_SIZE_TIMES 1
#define NSTACKX_P2P_INIT_SPEED_DIVISOR 2
/* DFile trans configuration */
#define NSTACKX_P2P_UDP_RTT 200
#define NSTACKX_P2P_MAX_CONTROL_FRAME_RETRY_COUNT 75
#define NSTACKX_P2P_MAX_CONTROL_FRAME_TIMEOUT 10000
#define NSTACKX_P2P_MAX_FILE_HEADER_CONFIRM_FRAME_TIMEOUT 5000
#define NSTACKX_P2P_RECEIVED_LIMIT_ACK_INTERVAL 500
#define NSTACKX_P2P_RECEIVED_LAST_FRAME_ACK_INTERVAL 100
#define NSTACKX_P2P_RECEIVER_IDLE_INIT_TIMEOUT 10000
#define NSTACKX_P2P_RECEIVER_IDLE_MAX_COUNT 1
#define NSTACKX_P2P_MAX_RETRY_PAGE_COUNT 16
#define NSTACKX_P2P_MIN_RETRY_PAGE_COUNT 3
#define NSTACKX_P2P_MAX_RETRY_LIST_NODE_NUM 100000
#define NSTACKX_P2P_WRITE_ALL_FILE_DATA_TIMEOUT 10000
#define NSTACKX_P2P_CLINET_SEND_THREAD_NUM_NON_GSO 3
#define NSTACKX_P2P_CLIENT_SEND_THREAD_NUM_GSO 1
#define NSTACKX_P2P_SEND_BLOCK_QUEUE_MAX_LEN 5000
#define NSTACKX_P2P_RECV_BLOCK_QUEUE_MAX_LEN 50000

#if (NSTACKX_P2P_CLINET_SEND_THREAD_NUM_NON_GSO > NSTACKX_MAX_CLIENT_SEND_THREAD_NUM) ||\
    (NSTACKX_P2P_CLIENT_SEND_THREAD_NUM_GSO > NSTACKX_MAX_CLIENT_SEND_THREAD_NUM)
#error OVER THE MAX SEND NUM!
#endif

/* for WLAN */
/* DFile session configuration */
#define NSTACKX_WLAN_SEND_RATE (30 * 1024 * 1024)
#define NSTACKX_WLAN_COMPENSATION_RATE 2
#define NSTACKX_WLAN_FRAME_SIZE_TIMES 1
#define NSTACKX_WLAN_INIT_SPEED_DIVISOR 2
#define NSTACKX_WLAN_INIT_RATE (3 * 1024 * 1024) /* can not get wifi rate  */

/* DFile trans configuration */
#define NSTACKX_WLAN_UDP_RTT 200
#define NSTACKX_WLAN_MAX_CONTROL_FRAME_RETRY_COUNT 75
#define NSTACKX_WLAN_MAX_CONTROL_FRAME_TIMEOUT 5000
#define NSTACKX_WLAN_MAX_FILE_HEADER_CONFIRM_FRAME_TIMEOUT 5000
#define NSTACKX_WLAN_RECEIVED_LIMIT_ACK_INTERVAL 500
#define NSTACKX_WLAN_RECEIVED_LAST_FRAME_ACK_INTERVAL 100
#define NSTACKX_WLAN_RECEIVER_IDLE_INIT_TIMEOUT 10000
#define NSTACKX_WLAN_RECEIVER_IDLE_MAX_COUNT 1
#define NSTACKX_WLAN_MAX_RETRY_PAGE_COUNT 16
#define NSTACKX_WLAN_MIN_RETRY_PAGE_COUNT 1
#define NSTACKX_WLAN_MAX_RETRY_LIST_NODE_NUM 50000
#define NSTACKX_WLAN_WRITE_ALL_FILE_DATA_TIMEOUT 1000
#define NSTACKX_WLAN_CLIENT_SEND_THREAD_NUM 1
#define NSTACKX_WLAN_CLIENT_SEND_THREAD_NUM_MP 2
#define NSTACKX_WLAN_SEND_BLOCK_QUEUE_MAX_LEN 1000
#define NSTACKX_WLAN_RECV_BLOCK_QUEUE_MAX_LEN 20000
/* thread name */
#define DFFILE_MAIN_THREAD_NAME "dfile_mainloop"
#define DFFILE_RECV_THREAD_NAME "dfile_recv"
#define DFFILE_SEND_THREAD_NAME_PREFIX "dfile_send_"
#define DFFILE_IO_THREAD_NAME_PREFIX "dfile_io_"
#define DFFILE_CONTROL_THREAD_NAME "dfile_control"

/* bind type */
typedef struct BindInfo {
    pid_t tid;
    uint32_t cpuMask;
} BindInfo;

#define DFILE_BIND_TYPE_INDEX_MAX 2
#define GSO_TYPE_INDEX_MAX 2
#define DFILE_MAX_THREAD_NUM 8

#define POS_IO_THERD_START 0
#define POS_SEND_THERD_START 3
#define POS_RECV_THERD_START 6
#define POS_MAIN_THERD_START 7

#define KEEP_ALIVE_IDLE 60
#define KEEP_ALIVE_CNT 5
#define KEEP_ALIVE_INTERVAL 1
#define TCP_USER_TIMEOUT_VALUE 60000

typedef enum {
    INIT_STATUS = -1,
    HIGH_SPEED = 0,
    LOW_SPEED,
} BindType;

#define SPEED_BOUNDS 120

typedef enum {
    STATE_TRANS_INIT = 0,
    STATE_TRANS_DONE,
} TransIdState;

struct DFileSession;

/* for function */
int32_t GetDFileConfig(DFileConfig *dFileConfig, uint16_t mtu, uint16_t connType);
int32_t ConfigDFileTrans(uint16_t connType, DFileTransConfig *transConfig);
void SetTidToBindInfo(const struct DFileSession *session, uint32_t pos);
void SetTcpKeepAlive(SocketDesc fd);
void DFileGetCipherCaps(struct DFileSession *session, SettingFrame *settingFramePara);
void DFileChooseCipherType(SettingFrame *hostSettingFrame, struct DFileSession *session);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef NSTACKX_DFILE_CONFIG_H */
