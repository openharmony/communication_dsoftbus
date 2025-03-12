/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#ifndef SOCKET_TYPE_H
#define SOCKET_TYPE_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_MAC_LEN  18
#define MAX_IP_LEN  46
#define MAX_PATH_LEN 4096
#define DEVICE_ID_LEN_MAX 65

/**
 * @brief Enumerates the data types.
 *
 * @since 2.0
 * @version 2.0
 */
typedef enum {
    DATA_TYPE_MESSAGE = 1,         /**< Message */
    DATA_TYPE_BYTES,               /**< Bytes */
    DATA_TYPE_FILE,                /**< File */
    DATA_TYPE_RAW_STREAM,          /**< Raw data stream */
    DATA_TYPE_VIDEO_STREAM,        /**< Video data stream */
    DATA_TYPE_AUDIO_STREAM,        /**< Audio data stream */
    DATA_TYPE_SLICE_STREAM,        /**< Video slice stream */
    DATA_TYPE_RAW_STREAM_ENCRYPED, /**< Encryped raw stream data */
    DATA_TYPE_BUTT,
} TransDataType;

typedef enum {
    EVENT_TYPE_CHANNEL_OPENED,
    EVENT_TYPE_TRANS_LIMIT_CHANGE,
    EVENT_TYPE_COLLAB_CHECK,
    EVENT_TYPE_BUTT,
} TransEventType;

/**
 * @brief Defines the description of the socket.
 *
 * @since 2.0
 * @version 2.0
 */
typedef struct {
    char *name;             /**< My socket name, maximum length 255 bytes */
    char *peerName;         /**< Peer socket name, maximum length 255 bytes */
    char *peerNetworkId;    /**< Peer network ID, maximum length 64 bytes */
    char *pkgName;          /**< Package name, maximum length 64 bytes */
    TransDataType dataType; /**< Data type */
} SocketInfo;

/**
 * @brief Defines the description of the socket.
 *
 * @since 2.0
 * @version 2.0
 */
typedef struct {
    char *name;              /**< Peer socket name, maximum length 255 bytes */
    char *networkId;         /**< Peer network ID, maximum length 64 bytes */
    char *pkgName;           /**< Peer package name, maximum length 64 bytes */
    TransDataType dataType; /**< Data type of peer socket*/
} PeerSocketInfo;

/**
 * @brief Enumerates the reason of the shutdown event.
 *
 * @since 2.0
 * @version 2.0
 */
typedef enum {
    SHUTDOWN_REASON_UNKNOWN,       /**< Shutdown for unknown reason */
    SHUTDOWN_REASON_LOCAL,         /**< Shutdown by local process */
    SHUTDOWN_REASON_PEER,          /**< Shutdown by peer process */
    SHUTDOWN_REASON_LNN_CHANGED,   /**< Shutdown for LNN changed */
    SHUTDOWN_REASON_CONN_CHANGED,  /**< Shutdown for CONN Changed */
    SHUTDOWN_REASON_TIMEOUT,       /**< Shutdown for timeout */
    SHUTDOWN_REASON_SEND_FILE_ERR, /**< Shutdown for sending file error */
    SHUTDOWN_REASON_RECV_FILE_ERR, /**< Shutdown for receiving file error */
    SHUTDOWN_REASON_RECV_DATA_ERR, /**< Shutdown for receiving data error */
    SHUTDOWN_REASON_UNEXPECTED,    /**< Shutdown for unexpected reason */
    SHUTDOWN_REASON_SERVICE_DIED,  /**< Shutdown for death service */
    SHUTDOWN_REASON_LNN_OFFLINE,   /**< Shutdown for offline */
    SHUTDOWN_REASON_LINK_DOWN,     /**< Shutdown for link down */
    SHUTDOWN_REASON_USER_SWICTH,   /**< Shutdown for user switch */
    SHUTDOWN_REASON_PRIVILEGE_SHUTDOWN, /**< Shutdown for privilege shutdown */
} ShutdownReason;

/**
 * @brief Enumerates of the level of Round Trip Time.
 *
 * @since 2.0
 * @version 2.0
 */
typedef enum {
    RTT_LEVEL_DEFAULT = 0, /**< Default RTT level */
    RTT_LEVEL_LOW,     /**< Low RTT level, perfer low round trip time. */
} QosRttLevel;

/**
 * @brief Enumerates the Qos transform reliability.
 *
 * @since 2.0
 * @version 2.0
 */
typedef enum {
    QOS_RELIABILITY_NONE = 1, /**< Unreliable */
    QOS_RELIABILITY_FULL,     /**< Reliable */
    QOS_RELIABILITY_HALF,     /**< Semi-reliable */
    QOS_RELIABILITY_BUTT,
} QosTransReliability;

/**
 * @brief Enumerates the QoS Assurance Items.
 *
 * @since 2.0
 * @version 2.0
 */
typedef enum {
    QOS_TYPE_MIN_BW,            /**< Minimum bandwidth. */
    QOS_TYPE_MAX_WAIT_TIMEOUT = 1,  /**< Maximum timeout of Bind. */
    QOS_TYPE_MAX_LATENCY = 1,       /**< Maximum latency. */
    QOS_TYPE_MIN_LATENCY,       /**< Minimum latency. */
    QOS_TYPE_RTT_LEVEL,         /**< Level of round trip time. */
    QOS_TYPE_MAX_BUFFER,        /**< @reserved Maximum cache. */
    QOS_TYPE_FIRST_PACKAGE,     /**< @reserved First packet size. */
    QOS_TYPE_MAX_IDLE_TIMEOUT,  /**< Maximum idle time. */
    QOS_TYPE_TRANS_RELIABILITY, /**< @reserved Transmission reliability. */
    QOS_TYPE_TRANS_CONTINUOUS,   /**< Continuous transmission */
    QOS_TYPE_REUSE_BE,           /**< Best Effort Reuse >**/
    QOS_TYPE_BUTT,
} QosType;

/**
 * @brief Defines the Qos Type-Value structure.
 *
 * @since 2.0
 * @version 2.0
 */
typedef struct {
    QosType qos;   /**< Qos type {@link QosType} */
    int32_t value; /**< Value of Qos types */
} QosTV;

/**
 * @brief Enumerates the file priority.
 *
 * @since 2.0
 * @version 2.0
 */
typedef enum {
    FILE_PRIORITY_TYPE_DEFAUT = 0, /**< Default priority */
    FILE_PRIORITY_TYPE_LOW,        /**< Low priority */
} FilePriority;

/**
 * @brief Enumerates the file types.
 *
 * @since 2.0
 * @version 2.0
 */
typedef enum {
    FILE_EVENT_SEND_PROCESS,     /**< Sending file */
    FILE_EVENT_SEND_FINISH,      /**< Send file end */
    FILE_EVENT_SEND_ERROR,       /**< Send file failed */
    FILE_EVENT_RECV_UPDATE_PATH, /**< Update root directory*/
    FILE_EVENT_RECV_START,       /**< Receive file start */
    FILE_EVENT_RECV_PROCESS,     /**< Receiving file */
    FILE_EVENT_RECV_FINISH,      /**< Receive file end */
    FILE_EVENT_RECV_ERROR,       /**< Receive file failed */
    FILE_EVENT_TRANS_STATUS,     /**< Transmission status of the files */
    FILE_EVENT_TRANS_LIMIT_CHANGED, /**< Transmission limit changed */
    FILE_EVENT_BUTT,
} FileEventType;

typedef struct {
    char **files;     /**< File path */
    uint32_t fileCnt; /**< Count of the files */
} FileList;

typedef struct {
    FileList completedList;    /**< Completed file list */
    FileList notCompletedList; /**< Not completed file list */
    FileList notStartedList;   /**< Not started file list */
} FileStatusList;

typedef struct {
    FileEventType type;                  /**< Event data type of the files*/
    const char **files;                  /**< File path*/
    uint32_t fileCnt;                    /**< Count of the files*/
    uint64_t bytesProcessed;             /**< Send or receive bytes of the files*/
    uint64_t bytesTotal;                 /**< Total bytes of the files*/
    const char *(*UpdateRecvPath)(void); /**< Update file receiving directory*/
    FileStatusList statusList;           /**< File status list */
    int32_t errorCode;                   /**< Error code */
    uint32_t rate;                       /**< Rate of the file transmission */
    FilePriority filePriority;          /**< Priority of the file */
} FileEvent;

/**
 * @brief Defines the extended stream data.
 *
 * @since 2.0
 * @version 2.0
 */
typedef struct {
    int32_t type;  /**< Extended data type {@link TransEnumEventType} */
    int64_t value; /**< Value of the extended data */
} TV;

/**
 * @brief Defines the frame information for stream transmission.
 *
 * @since 1.0
 * @version 1.0
 */
typedef struct {
    int32_t frameType; /**< Frame type, which can be I-frame or P-frame. */
    int64_t timeStamp; /**< Timestamp. */
    int32_t seqNum;    /**< Sequence number. */
    int32_t seqSubNum; /**< Sequence number of the slice. */
    int32_t level;     /**< Scalable video coding level. <b>0</b> stands for the base level,
                        <b>1</b> for level 1, and <b>2</b> for level 2. */
    int32_t bitMap;    /**< Bitmap, which indicates the start or end slice of a frame. */
    int32_t tvCount;   /**< Number of scalable tag-values (TVs). */
    TV *tvList;        /**< Pointer to the TV list. */
} StreamFrameInfo;

/**
 * @brief Defines the stream data.
 *
 * @since 1.0
 * @version 1.0
 */
typedef struct {
    char *buf;  /**< Pointer to the buffer for storing the stream data */
    int bufLen; /**< Length of the buffer */
} StreamData;

/**
 * @brief Enumerates the socket option types.
 *
 * @since 2.0
 * @version 2.0
 */
typedef enum {
    OPT_TYPE_BEGIN,
    OPT_TYPE_MAX_BUFFER = OPT_TYPE_BEGIN,  /**< @reserved Maximum cache. */
    OPT_TYPE_FIRST_PACKAGE,                /**< @reserved First packet size. */
    OPT_TYPE_MAX_IDLE_TIMEOUT,             /**< @reserved Maximum idle time. */
    OPT_TYPE_SUPPORT_ACK,
    OPT_TYPE_NEED_ACK,
    OPT_TYPE_END,
} OptType;

/**
 * @brief Enumerates the socket option level types.
 *
 * @since 2.0
 * @version 2.0
 */
typedef enum {
    OPT_LEVEL_KERNEL,  /**< @reserved Kernel level option. */
    OPT_LEVEL_SOFTBUS, /**< @reserved Softbus level option. */
    OPT_LEVEL_BUTT,
} OptLevel;

typedef struct {
    int32_t socket;                 /**< Socket fd */
    const char *initFileName;       /**< Init file name */
    char newFileName[MAX_PATH_LEN]; /**< New file name */
} RenameParam;

typedef void (*OnRenameFileCallback)(RenameParam *renameParam);

/**
 * @brief Enumerate frame event status.
 *
 * @since 2.0
 * @version 2.0
 */
typedef enum {
    FRAME_UNSEND,
    FRAME_SENDING,
    FRAME_RETRING,
    FRAME_RECEIVED,
    FRAME_DROPPED,
    FRAME_UNMANAGED,
} FrameEvtStatus;

typedef struct {
    int32_t seq;
    int32_t level;
    int32_t subSeqNum;
    FrameEvtStatus status;
    uint32_t interval; /**< frame sending interval */
    uint32_t queueUsage; /**< send queue percentage of use */
    uint32_t cachedFrameCnt; /**< frame count in VTP */
} FrameEvtCbInfo;

typedef int (*OnFrameEvt)(int fd, const FrameEvtCbInfo *info);

/**
 * @brief Enumerate Collab Info.
 *
 * @since 2.0
 * @version 2.0
 */
typedef struct {
    char deviceId[DEVICE_ID_LEN_MAX];
    int32_t userId;
    int64_t accountId;
    uint64_t tokenId;
    int32_t pid;
} CollabInfo;
#ifdef __cplusplus
}
#endif
#endif // SOCKET_TYPE_H