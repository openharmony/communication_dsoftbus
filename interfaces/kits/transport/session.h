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

/**
 * @addtogroup SoftBus
 * @{
 *
 * @brief Provides high-speed, secure communication between devices.
 *
 * This module implements unified distributed communication capability management between
 * nearby devices, and provides link-independent device discovery and transmission interfaces
 * to support service publishing and data transmission.
 *
 * @since 1.0
 * @version 1.0
*/
/** @} */

/**
 * @file session.h
 *
 * @brief Declares unified data transmission interfaces.
 *
 * This file provides data transmission capabilities, including creating and removing a session server,
 * opening and closing sessions, receiving data, and querying basic session information. \n
 * After multiple nearby devices are discovered and networked, these interfaces can be used to
 * transmit data across devices. \n
 *
 * @since 1.0
 * @version 1.0
 */
#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief business type of session
 *
 * @since 1.0
 * @version 1.0
 */
typedef enum {
    TYPE_MESSAGE = 1,
    TYPE_BYTES,
    TYPE_FILE,
    TYPE_STREAM,
    TYPE_BUTT,
} SessionType;

typedef enum  {
    INVALID = -1,
    /*
     * Send any segment of a frame each time.
     */
    RAW_STREAM,
    /*
     * Send a whole video frame each time.
     */
    COMMON_VIDEO_STREAM,
    /*
     * Send a whole audio frame each time.
     */
    COMMON_AUDIO_STREAM,
    /*
     * Slice frame mode.
     */
    VIDEO_SLICE_STREAM,
} StreamType;

typedef enum  {
    LINK_TYPE_WIFI_WLAN_5G = 1,
    LINK_TYPE_WIFI_WLAN_2G = 2,
    LINK_TYPE_WIFI_P2P = 3,
    LINK_TYPE_BR = 4,
    LINK_TYPE_MAX = 4,
} LinkType;

/**
 * @brief session attribute.
 *
 * control the attribute of session.
 *
 * @since 1.0
 * @version 1.0
 */
typedef struct {
    /** @brief dataType{@link SessionType} */
    int dataType;
    int linkTypeNum;
    LinkType linkType[LINK_TYPE_MAX];
    union {
        struct StreamAttr {
            int streamType;
        } streamAttr;
    } attr;
} SessionAttribute;

typedef struct {
    char *buf;
    int bufLen;
} StreamData;

typedef struct {
    int type;
    int64_t value;
} TV;

typedef struct {
    int frameType;
    int64_t timeStamp;
    int seqNum;
    int seqSubNum;
    int level;
    int bitMap;
    int tvCount;
    TV *tvList;
} StreamFrameInfo;

typedef enum {
    QOS_IMPROVE = 0,
    QOS_RECOVER = 1
} QosQuality;

typedef enum {
    TRANS_STREAM_QUALITY_EVENT = 1,
    TRANS_CHANNEL_QUALITY_EVENT,
    TRANS_CAN_DELAY_EVENT,
    TRANS_CANT_DELAY_EVENT,
    QOS_EVENT_MAX
} QosEvent;

typedef enum {
    WIFI_CHANNEL_QUALITY = 1,
    FRAME_REALTIME_STATUS = 2,
    BANDWIDTH_ESTIMATE_VALUE = 3,
    JITTER_DETECTION_VALUE = 4,
    STREAM_TRAFFIC_STASTICS = 5,
} TransEnumEventType;

typedef struct {
    int32_t channel;
    int32_t score;
} WifiChannelQuality;

typedef struct {
    int32_t streamId;
    int32_t seqNum;
    int32_t level;
    int32_t transStatus;
    int32_t interval;
} FrameStatus;

typedef struct {
    uint32_t trend;
    uint32_t rate;  /* kbps */
} BandwidthDetection;

typedef struct {
    int32_t jitterLevel;
    uint32_t bufferTime;  /* ms */
} JitterEstimation;

typedef struct {
    uint64_t statisticsGotTime; /* time point that stream traficc statistics are obtained (ms) */
    uint64_t periodRecvBits;
    uint32_t pktNum;
    uint32_t periodRecvPkts;
    uint32_t periodRecvPktLoss;
    uint32_t periodRecvRate; /* kbps */
    uint64_t periodRecvRateBps; /* bps */
    uint32_t periodRtt; /* ms */
    uint32_t periodRecvPktLossHighPrecision; /* for example when lost rate is 1.10%, then 110 will returned */
    uint32_t periodSendLostPkts;
    uint32_t periodSendPkts;
    uint32_t periodSendPktLossHighPrecision; /* for example when lost rate is 1.10%, then 110 will returned */
    uint64_t periodSendBits;
    uint64_t periodSendRateBps; /* bps */
} StreamStatistics;

typedef struct {
    TransEnumEventType type;
    union {
        WifiChannelQuality wifiChannelInfo;
        FrameStatus frameStatusInfo;
        BandwidthDetection bandwidthInfo;
        JitterEstimation jitterInfo;
        StreamStatistics appStatistics;
    } info;
} QosTv;

typedef enum {
    /* Value type of this option is uint32_t, this option only can be get */
    SESSION_OPTION_MAX_SENDBYTES_SIZE = 0,
    /* Value type of this option is uint32_t, this option only can be get */
    SESSION_OPTION_MAX_SENDMESSAGE_SIZE,

    SESSION_OPTION_BUTT,
} SessionOption;

/**
 * @brief Defines session callbacks.
 *
 * When a session is opened or closed, or there is data to process, the related callback is invoked.
 *
 * @since 1.0
 * @version 1.0
 */
typedef struct {
    /**
     * @brief Called when a session is opened.
     *
     * This function can be used to verify the session or initialize resources related to the session.
     *
     * @param sessionId Indicates the session ID.
     * @param result 0 if the session is opened successfully, returns an error code otherwise.
     * @return Returns <b>0</b> if the session connection is accepted; returns a non-zero value
     * otherwise (you do not need to call {@link CloseSession} to close the session).
     * @since 1.0
     * @version 1.0
     */
    int (*OnSessionOpened)(int sessionId, int result);

    /**
     * @brief Called when a session is closed.
     *
     * This function can be used to release resources related to the session.
     * You do not need to call {@link CloseSession}.
     *
     * @param sessionId Indicates the session ID.
     * @since 1.0
     * @version 1.0
     */
    void (*OnSessionClosed)(int sessionId);

    /**
     * @brief Called when data is received.
     *
     * This function is used to notify that data is received.
     *
     * @param sessionId Indicates the session ID.
     * @param data Indicates the pointer to the data received.
     * @param dataLen Indicates the length of the data received.
     * @since 1.0
     * @version 1.0
     */
    void (*OnBytesReceived)(int sessionId, const void *data, unsigned int dataLen);

    /**
     * @brief Called when message is received.
     *
     * This function is used to notify that message is received.
     *
     * @param sessionId Indicates the session ID.
     * @param data Indicates the pointer to the message data received.
     * @param dataLen Indicates the length of the message received.
     * @since 1.0
     * @version 1.0
     */
    void (*OnMessageReceived)(int sessionId, const void *data, unsigned int dataLen);

    /**
     * @brief Called when stream is received.
     *
     * This function is used to notify that stream is received.
     *
     * @param sessionId Indicates the session ID.
     * @param data Indicates the pointer to the stream data received.
     * @param dataLen Indicates the length of the stream received.
     * @since 1.0
     * @version 1.0
     */
    void (*OnStreamReceived)(int sessionId, const StreamData *data, const StreamData *ext,
        const StreamFrameInfo *param);

    /**
     * @brief Called when QoS information is retrieved.
     *
     * This function is used to notify that QoS information is retrieved.
     *
     * @param sessionId Indicates the session ID.
     * @param eventId Indicates the type of QoS information, e.g., channel quality and stream quality
     * @param tvCount Indicates the number of structure returned in the fourth parameters, i.e., tvList.
     * @param tvList Indicates the detailed information of data transmission.
     * @since 1.0
     * @version 1.0
     */
    void (*OnQosEvent)(int sessionId, int eventId, int tvCount, const QosTv *tvList);
} ISessionListener;

typedef struct {
    int (*OnReceiveFileStarted)(int sessionId, const char *files, int fileCnt);
    int (*OnReceiveFileProcess)(int sessionId, const char *firstFile, uint64_t bytesUpload, uint64_t bytesTotal);
    void (*OnReceiveFileFinished)(int sessionId, const char *files, int fileCnt);
    void (*OnFileTransError)(int sessionId);
} IFileReceiveListener;

typedef struct {
    int (*OnSendFileProcess)(int sessionId, uint64_t bytesUpload, uint64_t bytesTotal);
    int (*OnSendFileFinished)(int sessionId, const char *firstFile);
    void (*OnFileTransError)(int sessionId);
} IFileSendListener;

/**
 * @brief Creates a session server based on a package name and session name.
 *
 * A maximum of 10 session servers can be created.
 *
 * @param pkgName Indicates the pointer to the package name, which can be used to check whether the
 * session server is in this package. The value cannot be empty and can contain a maximum of 64 characters.
 * @param sessionName Indicates the pointer to the session name, which is the unique ID of the session server.
 * The value cannot be empty and can contain a maximum of 255 characters.
 * @param listener Indicates the pointer to the session callback structure, which cannot be empty.
 * The common error codes are as follows:
 * @return Returns <b>0</b> if the operation is successful; returns <b>-1</b> otherwise.
 * @see RemoveSessionServer
 * @since 1.0
 * @version 1.0
 */
int CreateSessionServer(const char *pkgName, const char *sessionName, const ISessionListener *listener);

/**
 * @brief Removes a session server based on a package name and session name.
 *
 * @param pkgName Indicates the pointer to the name of the registered package, which can be used to check
 * whether the session server is in this package. The value cannot be empty and can contain a maximum of 64 characters.
 * @param sessionName Indicates the pointer to the session name. The value cannot be empty and can contain
 * a maximum of 64 characters.
 * The common error codes are as follows:
 * @return Returns <b>0</b> if the operation is successful, returns <b>-1</b> otherwise.
 * @see CreateSessionServer
 * @since 1.0
 * @version 1.0
 */
int RemoveSessionServer(const char *pkgName, const char *sessionName);

/**
 * @brief Initiate a session open request, which is an asynchronous process.
 *
 * The session connection is opened based on the service name to trigger the first packet interaction process.
 * According to the {@link OnSessionOpened} Notify the user whether the session is successfully opened.
 * Data can be transmitted only after the session is successfully opened.
 *
 * @param mySessionName local session name.
 * @param peerSessionName remote session name.
 * @param peerNetworkId remote device id.
 * @param groupId group id.
 * @param attr session attribute {@link SessionAttribute}.
 * The common error codes are as follows:
 * @return <b>SOFTBUS_TRANS_INVALID_PARAM</b> invalid param.
 * @return <b>INVALID_SESSION_ID</b> open session failed, and return invalid session id.
 * @return return sessionId if the session is opened successfully,
 * and the sessionId is greater than 0, returns other internal error codes otherwise.
 * @since 1.0
 * @version 1.0
 */
int OpenSession(const char *mySessionName, const char *peerSessionName, const char *peerNetworkId,
    const char *groupId, const SessionAttribute* attr);

/**
 * @brief Closes a connected session based on a session ID.
 *
 * @param sessionId Indicates the session ID.
 * @return no return value.
 * @since 1.0
 * @version 1.0
 */
void CloseSession(int sessionId);

/**
 * @brief Sends data based on a session ID.
 *
 * @param sessionId Indicates the session ID.
 * @param data Indicates the pointer to the data to send, which cannot be <b>NULL</b>.
 * @param len Indicates the length of the data to send. The maximum length cannot exceed 984 characters.
 * The common error codes are as follows:
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> param data or len of value is invalid.
 * @return Returns <b>SOFTBUS_TRANS_SEND_LEN_BEYOND_LIMIT</b> The data length exceeds the maximum limit.
 * @return Returns <b>SOFTBUS_TRANS_INVALID_SESSION_ID</b> invalid session id.
 * @return Returns <b>SOFTBUS_TRANS_SESSION_NO_ENABLE</b> session is currently disable.
 * @return Returns <b>SOFTBUS_OK</b> if the function is called successfully, return other internal errorcode otherwise.
 * @since 1.0
 * @version 1.0
 */
int SendBytes(int sessionId, const void *data, unsigned int len);

/**
 * @brief Sends message based on a session ID.
 *
 * @param sessionId Indicates the session ID.
 * @param data Indicates the pointer to the message data to send, which cannot be <b>NULL</b>.
 * @param len Indicates the length of the message to send.
 * The common error codes are as follows:
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if the input data is NULL or len is Zero.
 * @return Returns <b>SOFTBUS_TRANS_SEND_LEN_BEYOND_LIMIT</b> The data length exceeds the maximum limit.
 * @return Returns <b>SOFTBUS_INVALID_SESSION_ID</b> if the sessionId is invalid.
 * @return Returns <b>SOFTBUS_TRANS_SESSION_NO_ENABLE</b> if the session current be enabled.
 * @return Returns <b>SOFTBUS_OK</b> if the function is called successfully, return other internal errorcode otherwise.
 * @since 1.0
 * @version 1.0
 */
int SendMessage(int sessionId, const void *data, unsigned int len);

/**
 * @brief Sends stream based on a session ID.
 *
 * @param sessionId Indicates the session ID.
 * @param data Indicates the pointer to the stream data to send, which cannot be <b>NULL</b>.
 * @param ext Indicates the pointer to the ext stream data to send, which cannot be <b>NULL</b>.
 * @param param Indicates the pointer to the stream data of param, which cannot be <b>NULL</b>.
 * The common error codes are as follows:
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if the input param is NULL.
 * @return Returns <b>SOFTBUS_INVALID_SESSION_ID</b> if the sessionId is invalid.
 * @return Returns <b>SOFTBUS_TRANS_SESSION_NO_ENABLE</b> if the session current be enabled.
 * @return Returns <b>SOFTBUS_OK</b> if the function is called successfully, return other internal errorcode otherwise.
 * @since 1.0
 * @version 1.0
 */
int SendStream(int sessionId, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param);

/**
 * @brief Obtains the session name registered by the local device based on the session ID.
 *
 * @param sessionId Indicates the session ID.
 * @param sessionName Indicates the pointer to the buffer for storing the session name.
 * @param len Indicates the length of the buffer.
 * The common error codes are as follows:
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> Indicates invalid value for input param.
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful, returns other internal error codes otherwise.
 * @since 1.0
 * @version 1.0
 */
int GetMySessionName(int sessionId, char *sessionName, unsigned int len);

/**
 * @brief Obtains the session name registered by the peer device based on the session ID.
 *
 * @param sessionId Indicates the session ID.
 * @param sessionName Indicates the pointer to the buffer for storing the session name.
 * @param len Indicates the length of the buffer.
 * The common error codes are as follows:
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> Indicates invalid value for input param.
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful, returns other internal error codes otherwise.
 * @since 1.0
 * @version 1.0
 */
int GetPeerSessionName(int sessionId, char *sessionName, unsigned int len);

/**
 * @brief Obtains the peer device ID based on a session ID.
 *
 * @param sessionId Indicates the session ID.
 * @param networkId Indicates the pointer to the buffer for storing the device ID.
 * @param len Indicates the length of the buffer.
 * The common error codes are as follows:
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> Indicates invalid value for input param.
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful, returns other internal error codes otherwise.
 * @since 1.0
 * @version 1.0
 */
int GetPeerDeviceId(int sessionId, char *networkId, unsigned int len);

/**
 * @brief Get session side based on a session ID.
 *
 * @param sessionId Indicates the session ID.
 * @return Returns <b>-1</b> Indicates get session side failed.
 * @return Returns <b>0</b> Indicates the session is server side.
 * @return Returns <b>1</b> Indicates the session is client side.
 * @since 1.0
 * @version 1.0
 */
int GetSessionSide(int sessionId);

/**
 * @brief Set file receive listener.
 *
 * @param pkgName Indicates the pointer to the name of the registered package, which can be used to check
 * whether the session server is in this package. The value cannot be empty and can contain a maximum of 64 characters.
 * @param sessionName Indicates the pointer to the buffer for storing the session name.
 * @param recvListener Indicates the pointer to the file receive listener, which cannot be <b>NULL</b>.
 * @param rootDir Indicates the length of the message to send.
 * The common error codes are as follows:
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> Indicates invalid value for input param.
 * @return Returns <b>SOFTBUS_TRANS_SESSION_ADDPKG_FAILED</b> if add pkgName failed.
 * @return Returns <b>SOFTBUS_OK</b>if the function is called successfully, return other internal errorcodes otherwise.
 * @since 1.0
 * @version 1.0
 */
int SetFileReceiveListener(const char *pkgName, const char *sessionName,
    const IFileReceiveListener *recvListener, const char *rootDir);

/**
 * @brief Set file sendListener based on pkgName and sessionName .
 *
 * @param pkgName Indicates the pointer to the name of the registered package, which can be used to check
 * whether the session server is in this package. The value cannot be empty and can contain a maximum of 64 characters.
 * @param sessionName Indicates the pointer to the buffer for storing the session name.
 * @param sendListener Indicates the pointer to the file send listener, which cannot be <b>NULL</b>.
 * The common error codes are as follows:
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if the input param is invalid.
 * @return Returns <b>SOFTBUS_TRANS_SESSION_ADDPKG_FAILED</b> if add pkgName failed.
 * @return Returns <b>SOFTBUS_OK</b>if the function is called successfully, return other internal errorcodes otherwise.
 * @since 1.0
 * @version 1.0
 */
int SetFileSendListener(const char *pkgName, const char *sessionName, const IFileSendListener *sendListener);

/**
 * @brief Sends file based on a session ID.
 *
 * @param sessionId Indicates the session ID.
 * @param sFileList Indicates the pointer to the source file list to send, which cannot be <b>NULL</b>.
 * @param dFileList Indicates the pointer to the destination file list to send, which cannot be <b>NULL</b>.
 * @param fileCnt Indicates the number of files to send, whic cannot be <b>0</b>.
 * The common error codes are as follows:
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if the sFileList is NULL or fileCnt is Zero.
 * @return Returns <b>SOFTBUS_INVALID_SESSION_ID</b> if the sessionId is invalid.
 * @return Returns <b>SOFTBUS_TRANS_SESSION_NO_ENABLE</b> if the session current be enabled.
 * @return Returns <b>SOFTBUS_OK</b>if the function is called successfully, return other internal errorcodes otherwise.
 * @since 1.0
 * @version 1.0
 */
int SendFile(int sessionId, const char *sFileList[], const char *dFileList[], uint32_t fileCnt);

/**
 * @brief Get Session based on a session ID.
 *
 * @param sessionId Indicates the session ID.
 * @param option Indicates the session option type to get.
 * @param optionValue Indicates the session option value to get, which cannot be <b>NULL</b>.
 * @param valueSize Indicates the size of data which optionValue point to, whic cannot be <b>0</b>.
 * The common error codes are as follows:
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if the option is invalid, optionValue is NULL or valueSize is Zero.
 * @return Returns <b>SOFTBUS_INVALID_SESSION_ID</b> if the sessionId is invalid.
 * @return Returns <b>SOFTBUS_TRANS_SESSION_NO_ENABLE</b> if the session current be not enabled.
 * @return Returns <b>SOFTBUS_OK</b>if the function is called successfully, return other internal errorcodes otherwise.
 * @since 1.0
 * @version 1.0
 */

int GetSessionOption(int sessionId, SessionOption option, void* optionValue, uint32_t valueSize);

#ifdef __cplusplus
}
#endif
#endif  // SESSION_H
