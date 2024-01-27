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

#include "client_trans_file.h"

#include <securec.h>
#include "client_trans_file_listener.h"
#include "file_adapter.h"
#include "nstackx_dfile.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "trans_log.h"

#define DEFAULT_KEY_LENGTH 32

static const UdpChannelMgrCb *g_udpChannelMgrCb = NULL;

static void NotifySendResult(int32_t sessionId, DFileMsgType msgType,
    const DFileMsg *msgData, FileListener *listener)
{
    if (msgData == NULL || listener == NULL) {
        return;
    }

    switch (msgType) {
        case DFILE_ON_FILE_SEND_SUCCESS:
            if (listener->sendListener.OnSendFileFinished != NULL) {
                listener->sendListener.OnSendFileFinished(sessionId, msgData->fileList.files[0]);
            }
            break;
        case DFILE_ON_FILE_SEND_FAIL:
            if (listener->sendListener.OnFileTransError != NULL) {
                listener->sendListener.OnFileTransError(sessionId);
            }
            break;
        case DFILE_ON_TRANS_IN_PROGRESS:
            if (listener->sendListener.OnSendFileProcess != NULL) {
                uint64_t bytesUpload = msgData->transferUpdate.bytesTransferred;
                uint64_t bytesTotal = msgData->transferUpdate.totalBytes;
                listener->sendListener.OnSendFileProcess(sessionId, bytesUpload, bytesTotal);
            }
            break;
        default:
            break;
    }
}

static void NotifySocketSendResult(int32_t socket, DFileMsgType msgType, const DFileMsg *msgData,
    const FileListener *listener)
{
    FileEvent event;
    switch (msgType) {
        case DFILE_ON_TRANS_IN_PROGRESS:
            event.type = FILE_EVENT_SEND_PROCESS;
            break;
        case DFILE_ON_FILE_SEND_SUCCESS:
            event.type = FILE_EVENT_SEND_FINISH;
            break;
        case DFILE_ON_FILE_SEND_FAIL:
            event.type = FILE_EVENT_SEND_ERROR;
            break;
        default:
            return;
    }

    event.files = msgData->fileList.files;
    event.fileCnt = msgData->fileList.fileNum;
    event.bytesProcessed = msgData->transferUpdate.bytesTransferred;
    event.bytesTotal = msgData->transferUpdate.totalBytes;
    event.UpdateRecvPath = NULL;
    listener->fileCallback(socket, &event);
}

static void FileSendListener(int32_t dfileId, DFileMsgType msgType, const DFileMsg *msgData)
{
    TRANS_LOGI(TRANS_FILE, "send dfileId=%{public}d type=%{public}d", dfileId, msgType);
    if (msgData == NULL || msgType == DFILE_ON_BIND || msgType == DFILE_ON_SESSION_IN_PROGRESS ||
        msgType == DFILE_ON_SESSION_TRANSFER_RATE) {
        TRANS_LOGE(TRANS_SDK, "param invalid");
        return;
    }
    UdpChannel udpChannel;
    (void)memset_s(&udpChannel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    if (TransGetUdpChannelByFileId(dfileId, &udpChannel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "trans get udp channel failed");
        return;
    }
    if (msgType == DFILE_ON_CONNECT_SUCCESS) {
        g_udpChannelMgrCb->OnUdpChannelOpened(udpChannel.channelId);
        TRANS_LOGE(TRANS_SDK, "msgType failed");
        return;
    }

    FileListener fileListener;
    (void)memset_s(&fileListener, sizeof(FileListener), 0, sizeof(FileListener));
    if (TransGetFileListener(udpChannel.info.mySessionName, &fileListener) != SOFTBUS_OK) {
        return;
    }

    int32_t sessionId = -1;
    if (g_udpChannelMgrCb->OnFileGetSessionId(udpChannel.channelId, &sessionId) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get sessionId failed");
        return;
    }

    if (msgType == DFILE_ON_CONNECT_FAIL || msgType == DFILE_ON_FATAL_ERROR) {
        if (fileListener.fileCallback != NULL) {
            FileEvent event;
            (void)memset_s(&event, sizeof(FileEvent), 0, sizeof(FileEvent));
            event.type = FILE_EVENT_SEND_ERROR;
            fileListener.fileCallback(sessionId, &event);
        } else if (fileListener.sendListener.OnFileTransError != NULL) {
            fileListener.sendListener.OnFileTransError(sessionId);
        }
        TRANS_LOGI(TRANS_SDK, "OnFile error. msgType=%{public}d", msgType);
        TransOnUdpChannelClosed(udpChannel.channelId, SHUTDOWN_REASON_SEND_FILE_ERR);
        return;
    }
    (void)g_udpChannelMgrCb->OnIdleTimeoutReset(sessionId);
    if (fileListener.fileCallback != NULL) {
        NotifySocketSendResult(sessionId, msgType, msgData, &fileListener);
    } else {
        NotifySendResult(sessionId, msgType, msgData, &fileListener);
    }
}

static void NotifyRecvResult(int32_t sessionId, DFileMsgType msgType, const DFileMsg *msgData,
    FileListener *listener)
{
    if (msgData == NULL || listener == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid");
        return;
    }

    const char *firstFile = msgData->fileList.files[0];
    uint32_t fileNum = msgData->fileList.fileNum;
    switch (msgType) {
        case DFILE_ON_FILE_LIST_RECEIVED:
            if (listener->recvListener.OnReceiveFileStarted != NULL) {
                listener->recvListener.OnReceiveFileStarted(sessionId, firstFile, fileNum);
            }
            break;
        case DFILE_ON_FILE_RECEIVE_SUCCESS:
            if (listener->recvListener.OnReceiveFileFinished != NULL) {
                listener->recvListener.OnReceiveFileFinished(sessionId, firstFile, fileNum);
            }
            break;
        case DFILE_ON_FILE_RECEIVE_FAIL:
            if (listener->recvListener.OnFileTransError != NULL) {
                listener->recvListener.OnFileTransError(sessionId);
            }
            break;
        case DFILE_ON_TRANS_IN_PROGRESS:
            if (listener->recvListener.OnReceiveFileProcess != NULL) {
                uint64_t bytesUpload = msgData->transferUpdate.bytesTransferred;
                uint64_t bytesTotal = msgData->transferUpdate.totalBytes;
                listener->recvListener.OnReceiveFileProcess(sessionId, firstFile, bytesUpload, bytesTotal);
            }
            break;
        default:
            break;
    }
}

static void NotifySocketRecvResult(int32_t socket, DFileMsgType msgType, const DFileMsg *msgData,
    const FileListener *listener)
{
    FileEvent event;
    switch (msgType) {
        case DFILE_ON_FILE_LIST_RECEIVED:
            event.type = FILE_EVENT_RECV_START;
            break;
        case DFILE_ON_TRANS_IN_PROGRESS:
            event.type = FILE_EVENT_RECV_PROCESS;
            break;
        case DFILE_ON_FILE_RECEIVE_SUCCESS:
            event.type = FILE_EVENT_RECV_FINISH;
            break;
        case DFILE_ON_FILE_RECEIVE_FAIL:
            event.type = FILE_EVENT_RECV_ERROR;
            break;
        default:
            return;
    }

    event.files = msgData->fileList.files;
    event.fileCnt = msgData->fileList.fileNum;
    event.bytesProcessed = msgData->transferUpdate.bytesTransferred;
    event.bytesTotal = msgData->transferUpdate.totalBytes;
    event.UpdateRecvPath = NULL;
    listener->fileCallback(socket, &event);
}

static void FileReceiveListener(int32_t dfileId, DFileMsgType msgType, const DFileMsg *msgData)
{
    TRANS_LOGI(TRANS_FILE, "recv dfileId=%{public}d, type=%{public}d", dfileId, msgType);
    if (msgData == NULL || msgType == DFILE_ON_BIND || msgType == DFILE_ON_SESSION_IN_PROGRESS ||
        msgType == DFILE_ON_SESSION_TRANSFER_RATE) {
        TRANS_LOGE(TRANS_SDK, "param invalid");
        return;
    }
    UdpChannel udpChannel;
    (void)memset_s(&udpChannel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    if (TransGetUdpChannelByFileId(dfileId, &udpChannel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get udp channel failed");
        return;
    }

    FileListener fileListener;
    (void)memset_s(&fileListener, sizeof(FileListener), 0, sizeof(FileListener));
    if (TransGetFileListener(udpChannel.info.mySessionName, &fileListener) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get listener failed");
        return;
    }
    int32_t sessionId = -1;
    if (g_udpChannelMgrCb->OnFileGetSessionId(udpChannel.channelId, &sessionId) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get sessionId failed");
        return;
    }
    if (msgType == DFILE_ON_CONNECT_FAIL || msgType == DFILE_ON_FATAL_ERROR) {
        if (fileListener.fileCallback != NULL) {
            FileEvent event;
            (void)memset_s(&event, sizeof(FileEvent), 0, sizeof(FileEvent));
            event.type = FILE_EVENT_RECV_ERROR;
            fileListener.fileCallback(sessionId, &event);
        } else if (fileListener.recvListener.OnFileTransError != NULL) {
            fileListener.recvListener.OnFileTransError(sessionId);
        }
        TransOnUdpChannelClosed(udpChannel.channelId, SHUTDOWN_REASON_RECV_FILE_ERR);
        return;
    }
    (void)g_udpChannelMgrCb->OnIdleTimeoutReset(sessionId);
    if (fileListener.fileCallback != NULL) {
        NotifySocketRecvResult(sessionId, msgType, msgData, &fileListener);
    } else {
        NotifyRecvResult(sessionId, msgType, msgData, &fileListener);
    }
}

static int32_t UpdateFileRecvPath(int32_t channelId, FileListener *fileListener, int32_t fileSession)
{
    int32_t sessionId = -1;
    if (g_udpChannelMgrCb->OnFileGetSessionId(channelId, &sessionId) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get sessionId by channelId failed");
        return SOFTBUS_ERR;
    }

    if (fileListener->fileCallback != NULL) {
        FileEvent event;
        (void)memset_s(&event, sizeof(FileEvent), 0, sizeof(FileEvent));
        event.type = FILE_EVENT_RECV_UPDATE_PATH;
        fileListener->fileCallback(sessionId, &event);
        if (event.UpdateRecvPath == NULL) {
            TRANS_LOGE(TRANS_SDK, "UpdateRecvPath is null");
            return SOFTBUS_ERR;
        }

        const char *rootDir = event.UpdateRecvPath();
        char *absPath = realpath(rootDir, NULL);
        if (absPath == NULL) {
            TRANS_LOGE(TRANS_SDK,
                "rootDir not exist, rootDir=%{public}s, errno=%{public}d.",
                (rootDir == NULL ? "null" : rootDir), errno);
            return SOFTBUS_ERR;
        }

        if (strcpy_s(fileListener->rootDir, FILE_RECV_ROOT_DIR_SIZE_MAX, absPath) != EOK) {
            TRANS_LOGE(TRANS_SDK, "strcpy rootDir failed");
            SoftBusFree(absPath);
            return SOFTBUS_ERR;
        }
        SoftBusFree(absPath);
    }

    if (NSTACKX_DFileSetStoragePath(fileSession, fileListener->rootDir) != SOFTBUS_OK) {
        NSTACKX_DFileClose(fileSession);
        TRANS_LOGE(TRANS_SDK, "set storage path failed. rootDir=%{public}s", fileListener->rootDir);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransOnFileChannelOpened(const char *sessionName, const ChannelInfo *channel, int32_t *filePort)
{
    if (channel == NULL || filePort == NULL) {
        TRANS_LOGW(TRANS_FILE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t fileSession;

    uint32_t capabilityValue = channel->isUdpFile ? NSTACKX_WLAN_CAT_DIRECT : NSTACKX_WLAN_CAT_TCP;
    (void)NSTACKX_DFileSetCapabilities(NSTACKX_CAPS_UDP_GSO | NSTACKX_CAPS_WLAN_CATAGORY, capabilityValue);
    if (channel->isServer) {
        FileListener fileListener;
        (void)memset_s(&fileListener, sizeof(FileListener), 0, sizeof(FileListener));
        if (TransGetFileListener(sessionName, &fileListener) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_FILE, "get file listener failed");
            return SOFTBUS_ERR;
        }
        fileSession = StartNStackXDFileServer(channel->myIp, (uint8_t *)channel->sessionKey,
            DEFAULT_KEY_LENGTH, FileReceiveListener, filePort);
        if (fileSession < 0) {
            TRANS_LOGE(TRANS_FILE, "start file channel as server failed");
            return SOFTBUS_ERR;
        }
        if (g_udpChannelMgrCb->OnUdpChannelOpened(channel->channelId) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_FILE, "udp channel open failed.");
            NSTACKX_DFileClose(fileSession);
            *filePort = 0;
            return SOFTBUS_ERR;
        }
        if (UpdateFileRecvPath(channel->channelId, &fileListener, fileSession)) {
            TRANS_LOGE(TRANS_FILE, "update receive file path failed");
            NSTACKX_DFileClose(fileSession);
            *filePort = 0;
            return SOFTBUS_ERR;
        }
    } else {
        fileSession = StartNStackXDFileClient(channel->peerIp, channel->peerPort,
            (uint8_t *)channel->sessionKey, DEFAULT_KEY_LENGTH, FileSendListener);
        if (fileSession < 0) {
            TRANS_LOGE(TRANS_FILE, "start file channel as client failed");
            return SOFTBUS_ERR;
        }
    }
    return fileSession;
}

static void *TransCloseDFileProcTask(void *args)
{
    int32_t *dfileId = (int32_t *)args;
    TRANS_LOGI(TRANS_FILE, "rsync close dfileId=%{public}d.", *dfileId);
    NSTACKX_DFileClose(*dfileId);
    SoftBusFree(dfileId);
    return NULL;
}

void TransCloseFileChannel(int32_t dfileId)
{
    TRANS_LOGI(TRANS_FILE, "start close file channel, dfileId=%{public}d.", dfileId);
    SoftBusThreadAttr threadAttr;
    SoftBusThread tid;
    int32_t ret = SoftBusThreadAttrInit(&threadAttr);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "thread attr init failed, ret=%{public}d.", ret);
        return;
    }
    int32_t *args = (int32_t *)SoftBusCalloc(sizeof(int32_t));
    if (args == NULL) {
        TRANS_LOGE(TRANS_FILE, "close dfile calloc failed. dfileId=%{public}d", dfileId);
        return;
    }
    *args = dfileId;
    threadAttr.detachState = SOFTBUS_THREAD_DETACH;
    ret = SoftBusThreadCreate(&tid, &threadAttr, TransCloseDFileProcTask, args);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "create closed file thread failed, ret=%{public}d.", ret);
        SoftBusFree(args);
        return;
    }
}

void RegisterFileCb(const UdpChannelMgrCb *fileCb)
{
    if (fileCb == NULL) {
        TRANS_LOGE(TRANS_FILE, "param invalid");
        g_udpChannelMgrCb = NULL;
        return;
    }
    if (g_udpChannelMgrCb != NULL) {
        TRANS_LOGE(TRANS_FILE, "g_udpChannelMgrCb is null");
        return;
    }
    g_udpChannelMgrCb = fileCb;
}

int32_t TransSendFile(int32_t dfileId, const char *sFileList[], const char *dFileList[], uint32_t fileCnt)
{
    if (dFileList == NULL) {
        return NSTACKX_DFileSendFiles(dfileId, sFileList, fileCnt, NULL);
    }
    return NSTACKX_DFileSendFilesWithRemotePath(dfileId, sFileList, dFileList, fileCnt, NULL);
}