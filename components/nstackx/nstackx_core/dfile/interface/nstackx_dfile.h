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

#ifndef NSTACKX_DFILE_H
#define NSTACKX_DFILE_H

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

#if defined(_WIN32) || defined(_WIN64)
#include <WS2tcpip.h>
#define NSTACKX_EXPORT __declspec(dllexport)
#else
#include <ifaddrs.h>
#include <netinet/in.h>
#define NSTACKX_EXPORT extern
#endif

#include "nstackx_error.h"
#ifdef __cplusplus
extern "C" {
#endif

#ifdef NSTACKX_WITH_LITEOS
#define NSTACKX_DFILE_MAX_FILE_NUM 10
#else
#define NSTACKX_DFILE_MAX_FILE_NUM 500
#endif
#define NSTACKX_MAX_FILE_NAME_LEN 256
#define NSTACKX_MAX_PATH_LEN 256
#define NSTACKX_MAX_REMOTE_PATH_LEN 1024
/* Maximum sending list limit. Sending more than this value will fail. */
#ifdef NSTACKX_WITH_LITEOS
#define NSTACKX_MAX_FILE_LIST_NUM 10
#else
#define NSTACKX_MAX_FILE_LIST_NUM 500
#endif
#define NSTACKX_MAX_STORAGE_PATH_NUM 500
#define NSTACKX_RESERVED_TRANS_ID 0
#define NSTACKX_RESERVED_PATH_TYPE 0
#define NSTACKX_MULTI_PATH_NUM 2
/* 10MB VTRANS */
#define NSTACKX_VTRANS_DEFAULT_SIZE (10 * 1024 * 1024)
#define NSTACKX_VTRANS_STEP_SIZE (5 * 1024 * 1024)
#define NSTACKX_VTRANS_MAX_SIZE (1024 * 1024 * 1024)

#define CAPS_MULTIPATH 4

typedef struct DFileSession DFileSession;

/* DFile session message type list. */
typedef enum {
    DFILE_ON_CONNECT_SUCCESS = 1,
    DFILE_ON_CONNECT_FAIL,
    DFILE_ON_FILE_LIST_RECEIVED,
    DFILE_ON_FILE_RECEIVE_SUCCESS,
    DFILE_ON_FILE_RECEIVE_FAIL,
    DFILE_ON_FILE_SEND_SUCCESS,
    DFILE_ON_FILE_SEND_FAIL,
    DFILE_ON_FATAL_ERROR,
    DFILE_ON_SESSION_IN_PROGRESS,
    DFILE_ON_TRANS_IN_PROGRESS,
    DFILE_ON_SESSION_TRANSFER_RATE,
    DFILE_ON_BIND,
    DFILE_ON_CLEAR_POLICY_FILE_LIST,
} DFileMsgType;

enum {
    CAPS_UDP_GSO = 0,
    CAPS_LINK_SEQUENCE,
    CAPS_WLAN_CATAGORY,
    CAPS_NO_RTT,
    CAPS_RESERVED, /* for multipath check of old version */
    CAPS_ALG_NORATE, // NoRate algorithm
    CAPS_RESUMABLE_TRANS,
    CAPS_ZEROCOPY,
    /* add more capability here */
    CAPS_MAX,
};

#define NSTACKX_WLAN_CAT_2_4G               1U
#define NSTACKX_WLAN_CAT_5G                 2U
#define NSTACKX_WLAN_CAT_DIRECT             3U
#define NSTACKX_WLAN_CAT_TCP                4U

#define NSTACKX_RECV_BUFFER_LEN  1600

#define NBITS(n)                            (1U << (n))
#define NSTACKX_CAPS_UDP_GSO                NBITS(CAPS_UDP_GSO)
#define NSTACKX_CAPS_LINK_SEQUENCE          NBITS(CAPS_LINK_SEQUENCE)
#define NSTACKX_CAPS_WLAN_CATAGORY          NBITS(CAPS_WLAN_CATAGORY)
#define NSTACKX_CAPS_MULTIPATH              NBITS(CAPS_MULTIPATH)

#define NSTACKX_CAPS_MASK                   (NBITS(CAPS_MAX) - 1)

/*
 * DFile session message data. User should fetch corresponding member variable based on message type:
 *          DFileMsgType               Member variable
 *   DFILE_ON_CONNECT_SUCCESS            none
 *   DFILE_ON_CONNECT_FAIL               errorCode
 *   DFILE_ON_FILE_LIST_RECEIVED         fileList
 *   DFILE_ON_FILE_RECEIVE_SUCCESS       fileList and transferUpdate
 *   DFILE_ON_FILE_RECEIVE_FAIL          fileList, errorCode and transferUpdate. fileList maybe empty, as not all the
 *                                       file names are received.
 *   DFILE_ON_FILE_SEND_SUCCESS          fileList and transferUpdate
 *   DFILE_ON_FILE_SEND_FAIL             fileList, errorCode and transferUpdate.
 *   DFILE_ON_TRANS_IN_PROGRESS          transferUpdate and fileList. Transfer process update of target trans identified
 *                                       by the transId.
 *   DFILE_ON_SESSION_IN_PROGRESS        transferUpdate. Transfer process update of the whole session.
 *
 *   DFILE_ON_FATAL_ERROR                errorCode. DFileSession cannot be used any more, and should be destroyed.
 *   DFILE_ON_SESSION_TRANSFER_RATE      rate.
 *
 * It's invalid when for other message types.
 */
typedef enum {
    FILE_STAT_COMPLETE,     /* whole file transfered*/
    FILE_STAT_NOT_COMPLETE, /*file start transfered but not whole*/
    FILE_STAT_NOT_START,    /*file not start transfered*/
    FILE_STAT_BUTT,
} DFileFileStat;

typedef struct {
    char *file;
    DFileFileStat stat;
} DFileFileInfo;

typedef struct {
    struct {
        const char **files;
        uint32_t fileNum;
        uint16_t transId;
        char *userData;
    } fileList;
    struct {
        uint32_t fileNum;
        const DFileFileInfo *fileInfo;
    } clearPolicyFileList;
    struct {
        uint16_t transId;
        uint64_t totalBytes;
        uint64_t bytesTransferred;
    } transferUpdate;
    int32_t errorCode;
    uint32_t rate;
    struct sockaddr_in sockAddr[NSTACKX_MULTI_PATH_NUM];
} DFileMsg;

typedef struct {
    const char *files[NSTACKX_DFILE_MAX_FILE_NUM];
    const char *remotePath[NSTACKX_DFILE_MAX_FILE_NUM];
    const char *userData;
    uint32_t fileNum;
    uint16_t pathType;
    uint8_t tarFlag : 1;
    uint8_t smallFlag : 1;
    uint8_t unuse : 6;
} NSTACKX_FilesInfo;

typedef struct {
    uint16_t rootPathType;
    const char *initFileName;
    char newFileName[NSTACKX_MAX_REMOTE_PATH_LEN];
} DFileRenamePara;

/* Callback type for rename existing file */
typedef void (*OnDFileRenameFile)(DFileRenamePara *renamePara);

/* Callback type for DFile session message receiver. */
typedef void (*DFileMsgReceiver)(int32_t sessionId, DFileMsgType msgType, const DFileMsg *msg);

typedef struct {
    struct sockaddr_in *addr;
    socklen_t addrLen;
    const uint8_t *key;
    uint32_t keyLen;
    DFileMsgReceiver msgReceiver;
    const char *localInterfaceName;
} NSTACKX_SessionPara;

typedef void (*DFileLogImpl)(const char *tag, uint32_t level, const char *format, va_list args);

typedef struct {
    struct sockaddr_in *addr;
    socklen_t addrLen;
    const char *localInterfaceName;
} NSTACKX_SessionParaMp;

typedef struct {
    struct sockaddr_in *addr;
    socklen_t addrLen;
} NSTACKX_ServerParaMp;

/* nStack HIEVENT接口设计 */
typedef enum {
    DFile_EVENT_TYPE_FAULT,
    DFile_EVENT_TYPE_STATISTIC,
    DFile_EVENT_TYPE_SECURITY,
    DFile_EVENT_TYPE_BEHAVIOR,
} DFileEventType;

typedef enum {
    DFile_EVENT_LEVEL_CRITICAL,
    DFile_EVENT_LEVEL_MINOR,
} DFileEventLevel;

typedef enum {
    DFile_PARAM_TYPE_BOOL,
    DFile_PARAM_TYPE_UINT8,
    DFile_PARAM_TYPE_UINT16,
    DFile_PARAM_TYPE_INT32,
    DFile_PARAM_TYPE_UINT32,
    DFile_PARAM_TYPE_UINT64,
    DFile_PARAM_TYPE_FLOAT,
    DFile_PARAM_TYPE_DOUBLE,
    DFile_PARAM_TYPE_STRING
} DFileEventParamType;

enum {
    DFILE_LOG_LEVEL_OFF     = 0,
    DFILE_LOG_LEVEL_FATAL   = 1,
    DFILE_LOG_LEVEL_ERROR   = 2,
    DFILE_LOG_LEVEL_WARNING = 3,
    DFILE_LOG_LEVEL_INFO    = 4,
    DFILE_LOG_LEVEL_DEBUG   = 5,
    DFILE_LOG_LEVEL_END,
};

#define DFile_EVENT_NAME_LEN 33
#define DFile_EVENT_TAG_LEN 16

typedef struct {
    DFileEventParamType type;
    char name[DFile_EVENT_NAME_LEN];
    union {
        uint8_t u8v;
        uint16_t u16v;
        int32_t i32v;
        uint32_t u32v;
        uint64_t u64v;
        float f;
        double d;
        char str[DFile_EVENT_NAME_LEN];
    } value;
} DFileEventParam;

typedef struct {
    char eventName[DFile_EVENT_NAME_LEN];
    DFileEventType type;
    DFileEventLevel level;
    uint32_t paramNum;
    DFileEventParam *params;
} DFileEvent;

/*
 * Create DFile server session.
 * param: localAddr - filled with local ip addr, port and family for socket binding
 *                    the ip addr and port must be host order
 * param: addrLen - localAddr length
 * param: key - key for data encrypt or decrypt, should be a 16 bytes string.
 * param: msgReceiver - event callback for user
 * return positive session id on success, negative value on failure
 */
NSTACKX_EXPORT int32_t NSTACKX_DFileServer(struct sockaddr_in *localAddr, socklen_t addrLen, const uint8_t *key,
                                           uint32_t keyLen, DFileMsgReceiver msgReceiver);


/*
 * Create DFile client session.
 * param: srvAddr - filled with remote ip addr, port and family, the ip addr and port must be host order
 * param: addrLen - srvAddr length
 * param: key - key for data encrypt or decrypt. It should be a 16 bytes buffer if this session is used to transfer
 *              file with crypto, or NULL if transfer without crypto.
 * param: keyLen - keyLen for the key. It should be 16 if this session is used to transfer file with crypto, or 0
 *                 if transfer without crypto.
 * param: msgReceiver - event callback for user
 * return positive session id on success, negative value on failure
 */
NSTACKX_EXPORT int32_t NSTACKX_DFileClient(struct sockaddr_in *srvAddr, socklen_t addrLen, const uint8_t *key,
                                           uint32_t keyLen, DFileMsgReceiver msgReceiver);

/*
 * Create DFile client session on target device.
 * param: sessionInfo->srvAddr - filled with remote ip addr, port and family, the ip addr and port must be host order
 * param: sessionInfo->addrLen - srvAddr length
 * param: sessionInfo->key - key for data encrypt or decrypt. It should be a 16 bytes buffer if this session is used to
 *                           transfer file with crypto, or NULL if transfer without crypto.
 * param: sessionInfo->keyLen - keyLen for the key. It should be 16 if this session is used to transfer file with
 *                              crypto, or 0 if transfer without crypto.
 * param: sessionInfo->msgReceiver - event callback for user
 * param: sessionInfo->localInterfaceName - The full name of the target device for the socket of the session to bind.
 *                                          If this param is NULL, the session's socket will bind to the device in the
 *                                          same LAN with the srvAddr, but it may be inaccurate under certain
 *                                          conditions. *
 * return positive session id on success, negative value on failure
 */
NSTACKX_EXPORT int32_t NSTACKX_DFileClientWithTargetDev(NSTACKX_SessionPara *sessionPara);

/* Close session instance. */
NSTACKX_EXPORT void NSTACKX_DFileClose(int32_t sessionId);

/*
 * Start to send files by client session.
 * param: files - File name list.to be sent.
 * param: fileNum - Number of elements in "files".
 * param: userData - user context data for each Send Files.
 * return 0 on success, negative value on failure
 */
NSTACKX_EXPORT int32_t NSTACKX_DFileSendFiles(int32_t sessionId, const char *files[], uint32_t fileNum,
                                              const char *userData);

/*
 * Start to send files by client session assign the storage dir of this files for server.
 * param: files - File name list.to be sent.
 * param: remotePath - The remote path(including file name) list of files for the server to save them.
 * param: fileNum - Number of elements in "files".
 * param: userData - user context data for each Send Files.
 * return 0 on success, negative value on failure
 */
NSTACKX_EXPORT int32_t NSTACKX_DFileSendFilesWithRemotePath(int32_t sessionId, const char *files[],
    const char *remotePath[], uint32_t fileNum, const char *userData);

/*
 * Start to send files by client session and assign the storage dir of this files for server. The storage dir contains
 * a root path and a relative dir(including filename). The root dir is set by the server, who may has set more than and
 * will chose one who has the same type as the filesInfo->pathType. The relative path is filesInfo->remotePath.
 * param: filesInfo->files - File name list.to be sent.
 * param: filesInf->remotePath - The remote path list of files.
 * param: filesInfo->fileNum - Number of elements in "files".
 * param: filesInfo->userData - User context data for each Send Files.
 * param: filesInfo->pathType - The type of the fileInfo->files. It determines which root path the server will storage
 *                              these files. Whats more, transfer will be failed if the server can't find the root path
 *                              with tha same type.
 * param: filesInfo->tarFlag - If it is true, this files will be packaged to a tar file and sent. Otherwise, they will
 *                             be sent separately.
 * param: filesInfo->smallflag - If it is true, means all files of the list are small files. the files will try to send
 *                               with big files side-by-side.
 * return 0 on success, negative value on failure
 */
NSTACKX_EXPORT int32_t NSTACKX_DFileSendFilesWithRemotePathAndType(int32_t sessionId, NSTACKX_FilesInfo *filesInfo);

/*
 * Set storage path for server session. Note that it will move the files that already recevied to this new path.
 * New incoming files will also be save to here.
 * return 0 on success, negative value on failure
 */
NSTACKX_EXPORT int32_t NSTACKX_DFileSetStoragePath(int32_t sessionId, const char *path);

/*
 * Set callback for server to rename a new file when there is an existing file with the same dir and name.
 * If this is not called, the existing file will be overwritte by the new received file with the same dir and name.
 */
NSTACKX_EXPORT int32_t NSTACKX_DFileSetRenameHook(int32_t sessionId, OnDFileRenameFile onRenameFile);

/*
 * Set storage paths for diffreant types of files for server session.
 * Note that it will move the files that already recevied to this new path.
 * For the same sessionId, only one of this interface and the NSTACKX_DFileSetStoragePath() can be used.
 * New incoming files will also be save to one of these path who has the same type. If the incoming files't type isn't
 * one of the pathType list, these files will be refused
 * return 0 on success, negative value on failure
 */
NSTACKX_EXPORT int32_t NSTACKX_DFileSetStoragePathList(int32_t sessionId, const char *path[], const uint16_t *pathType,
                                                       uint16_t pathNum);

/*
 * Set the log implementation
 */
NSTACKX_EXPORT int32_t NSTACKX_DFileRegisterLog(DFileLogImpl logImpl);

/*
 * Get/Set the DFILE capabilities
 */
NSTACKX_EXPORT uint32_t NSTACKX_DFileGetCapabilities(void);

NSTACKX_EXPORT int32_t NSTACKX_DFileSetCapabilities(uint32_t capabilities, uint32_t value);

typedef void (*DFileDumpFunc)(void *softObj, const char *data, uint32_t len);

NSTACKX_EXPORT int32_t NSTACKX_DFileDump(uint32_t argc, const char **arg, void *softObj, DFileDumpFunc dump);

/* 软总线提供的回调支持多线程调用，事件的触发频率要求(表格整理出来，什么时候触发，触发频率) */
typedef void (*DFileEventFunc)(void *softObj, const DFileEvent *info);

NSTACKX_EXPORT void NSTACKX_DFileSetEventFunc(void *softObj, DFileEventFunc func);

typedef void (*DFileLogCallback)(const char *moduleName, uint32_t logLevel, const char *format, ...);

/*
 * Set the DFile log implementation
 */
NSTACKX_EXPORT int32_t NSTACKX_DFileRegisterLogCallback(DFileLogCallback userLogCallback);
NSTACKX_EXPORT void NSTACKX_DFileRegisterDefaultLog(void);

/**
 * get DFILE_ON_CLEAR_POLICY_FILE_LIST event callback.
 * @brief Gets file list with file state
 * @param[in] sessionId the session id of the session
 * @return 0 on success, negative value on failure
 */
NSTACKX_EXPORT int32_t NSTACKX_DFileSessionGetFileList(int32_t sessionId);

typedef enum {
    /* the priority of socket, value is same as IP_TOS, vallen is siezeof(uint8_t) */
    OPT_TYPE_SOCK_PRIO,
    OPT_TYPE_BUTT
} DFileOptType;

typedef struct {
    DFileOptType optType;
    uint32_t valLen; /* length of value */
    uint64_t value;  /* the option value, could be a pointer */
} DFileOpt;

/*
 * set dfile session opt
 * @brief Sets DFile session options. for client session, Recommend to configure after DFILE_ON_CONNECT_SUCCESS.
 * @param[in] sessionId the session id of the session
 * @param[in] opt option tlv
 * @return 0 on success, negative value on failure
 */
NSTACKX_EXPORT int32_t NSTACKX_DFileSetSessionOpt(int32_t sessionId, const DFileOpt *opt);
#ifdef __cplusplus
}
#endif

#endif  /* #ifndef NSTACKX_DFILE_H */
