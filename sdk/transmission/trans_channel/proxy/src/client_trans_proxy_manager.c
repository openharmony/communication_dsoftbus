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

#include "client_trans_proxy_manager.h"

#include <errno.h>
#include <fcntl.h>
#include <securec.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "client_trans_session_manager.h"
#include "client_trans_tcp_direct_message.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_utils.h"
#include "trans_server_proxy.h"

static IClientSessionCallBack g_sessionCb;
static uint32_t g_authMaxByteBufSize;
static uint32_t g_authMaxMessageBufSize;
static SendFileInfo g_sendFileInfo = {
    .seqCount = 0,
    .seqLockInitFlag = false,
};

static RecvFileInfo g_recvFileInfo = {
    .sessionId = 0,
};

static void ProxyFileTransTimerProc(void);

#define BYTE_INT_NUM 4
#define BIT_INT_NUM 32
#define BIT_BYTE_NUM 8

int32_t ClinetTransProxyInit(const IClientSessionCallBack *cb)
{
    if (cb == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    g_sessionCb = *cb;
    if (g_sendFileInfo.seqLockInitFlag == false) {
        if (SoftBusMutexInit(&g_sendFileInfo.lock, NULL) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "sendfile mutex init fail!");
            return SOFTBUS_ERR;
        }
        g_sendFileInfo.seqLockInitFlag = true;
    }

    if (SoftBusMutexInit(&g_recvFileInfo.lock, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "recvfile mutex init fail!");
        return SOFTBUS_ERR;
    }

    if (RegisterTimeoutCallback(SOFTBUS_PROXY_SENDFILE_TIMER_FUN, ProxyFileTransTimerProc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "register sendfile timer fail");
    }

    if (SoftbusGetConfig(SOFTBUS_INT_AUTH_MAX_BYTES_LENGTH,
        (unsigned char*)&g_authMaxByteBufSize, sizeof(g_authMaxByteBufSize)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get auth proxy channel max bytes length fail");
    }
    if (SoftbusGetConfig(SOFTBUS_INT_AUTH_MAX_MESSAGE_LENGTH,
        (unsigned char*)&g_authMaxMessageBufSize, sizeof(g_authMaxMessageBufSize)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get auth proxy channel max message length fail");
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "proxy auth byteSize[%u], messageSize[%u]",
        g_authMaxByteBufSize, g_authMaxMessageBufSize);
    return SOFTBUS_OK;
}

int32_t ClientTransProxyOnChannelOpened(const char *sessionName, const ChannelInfo *channel)
{
    if (sessionName == NULL || channel == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    int ret = g_sessionCb.OnSessionOpened(sessionName, channel, TYPE_MESSAGE);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify session open fail");
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t ClientTransProxyOnChannelClosed(int32_t channelId)
{
    int ret = g_sessionCb.OnSessionClosed(channelId, CHANNEL_TYPE_PROXY);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify session openfail err");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ClientTransProxyOnChannelOpenFailed(int32_t channelId)
{
    int ret = g_sessionCb.OnSessionOpenFailed(channelId, CHANNEL_TYPE_PROXY);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify session openfail err");
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t ClientTransProxyOnDataReceived(int32_t channelId,
    const void *data, uint32_t len, SessionPktType type)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    int ret = g_sessionCb.OnDataReceived(channelId, CHANNEL_TYPE_PROXY, data, len, type);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify data recv err");
        return ret;
    }
    return SOFTBUS_OK;
}

void ClientTransProxyCloseChannel(int32_t channelId)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransCloseProxyChannel, channelId [%d]", channelId);
    if (ServerIpcCloseChannel(channelId, CHANNEL_TYPE_PROXY) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server close channel err");
    }
}

int32_t TransProxyChannelSendBytes(int32_t channelId, const void *data, uint32_t len)
{
#define PROXY_MAX_BYTES_LEN (4 * 1024)
    int32_t encryp = 0;
    int32_t ret = GetEncryptByChannelId(channelId, CHANNEL_TYPE_PROXY, &encryp);
    if (ret != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (encryp == 1) {
        if (len > PROXY_MAX_BYTES_LEN) {
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
    } else {
        if (len > g_authMaxByteBufSize) {
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
    }
    ret = ServerIpcSendMessage(channelId, CHANNEL_TYPE_PROXY, data, len, TRANS_SESSION_BYTES);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send bytes: channelId=%d, ret=%d", channelId, ret);
    return ret;
}

int32_t TransProxyChannelSendMessage(int32_t channelId, const void *data, uint32_t len)
{
#define PROXY_MAX_MESSAGE_LEN (1 * 1024)
    int32_t encryp = 0;
    int32_t ret = GetEncryptByChannelId(channelId, CHANNEL_TYPE_PROXY, &encryp);
    if (ret != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (encryp == 1) {
        if (len > PROXY_MAX_MESSAGE_LEN) {
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
    } else {
        if (len > g_authMaxMessageBufSize) {
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
    }
    ret = ServerIpcSendMessage(channelId, CHANNEL_TYPE_PROXY, data, len, TRANS_SESSION_MESSAGE);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send msg: channelId=%d, ret=%d", channelId, ret);
    return ret;
}

static bool IntToByte(int32_t value, char *buffer, int32_t len)
{
    if ((buffer == NULL) || (len < (int32_t)sizeof(int32_t))) {
        return false;
    }

    for (int32_t i = 0; i < BYTE_INT_NUM; i++) {
        int32_t offset = BIT_INT_NUM - (i + 1) * BIT_BYTE_NUM;
        buffer[i] = (char)((value >> offset) & 0xFF);
    }
    return true;
}

static bool ByteToInt(char *buffer, int32_t len, int32_t *outValue)
{
    if ((outValue == NULL) || (buffer == NULL) || (len < (int32_t)sizeof(int32_t))) {
        return false;
    }
    int32_t value = 0;
    for (int32_t i = 0; i < BYTE_INT_NUM; i++) {
        value <<= BIT_BYTE_NUM;
        value |= buffer[i] & 0xFF;
    }

    *outValue = value;
    return true;
}

static int32_t GetIdleIndexNode(int32_t *index)
{
    if (index == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "input index is null");
        return SOFTBUS_ERR;
    }
    int32_t i;
    for (i = 0; i < MAX_RECV_FILE_NUM; i++) {
        if (g_recvFileInfo.recvFileInfo[i].fileStatus == NODE_IDLE) {
            *index = i;
            return SOFTBUS_OK;
        }
    }

    if (i == MAX_RECV_FILE_NUM) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "there is no idle node");
        *index = INVALID_NODE_INDEX;
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t GetRecvFileInfoBySeq(uint32_t seq, SingleFileInfo *fileInfo)
{
    if (fileInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "fd is null");
        return SOFTBUS_ERR;
    }

    int32_t i;
    for (i = 0; i < MAX_RECV_FILE_NUM; i++) {
        if (g_recvFileInfo.recvFileInfo[i].seq == seq) {
            fileInfo->index = g_recvFileInfo.recvFileInfo[i].index;
            fileInfo->seq = seq;
            fileInfo->fileFd = g_recvFileInfo.recvFileInfo[i].fileFd;
            fileInfo->fileStatus = g_recvFileInfo.recvFileInfo[i].fileStatus;
            fileInfo->fileOffset = g_recvFileInfo.recvFileInfo[i].fileOffset;
            if (memcpy_s(fileInfo->filePath, MAX_REMOTE_PATH_LEN, g_recvFileInfo.recvFileInfo[i].filePath,
                MAX_REMOTE_PATH_LEN) != EOK) {
                return SOFTBUS_ERR;
            }
            return SOFTBUS_OK;
        }
    }

    if (i == MAX_RECV_FILE_NUM) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "there is no match seq to get");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t RemoveFromRecvListBySeq(uint32_t seq)
{
    int32_t i;
    for (i = 0; i < MAX_RECV_FILE_NUM; i++) {
        if (g_recvFileInfo.recvFileInfo[i].seq == seq) {
            g_recvFileInfo.recvFileInfo[i].index = 0;
            g_recvFileInfo.recvFileInfo[i].seq = 0;
            g_recvFileInfo.recvFileInfo[i].fileFd = INVALID_FD;
            g_recvFileInfo.recvFileInfo[i].fileStatus = NODE_IDLE;
            g_recvFileInfo.recvFileInfo[i].fileOffset = 0;
            g_recvFileInfo.recvFileInfo[i].timeOut = 0;
            memset_s(g_recvFileInfo.recvFileInfo[i].filePath, MAX_REMOTE_PATH_LEN, 0, MAX_REMOTE_PATH_LEN);
            memset_s(&g_recvFileInfo.fileListener, sizeof(FileListener), 0, sizeof(FileListener));
            return SOFTBUS_OK;
        }
    }

    if (i == MAX_RECV_FILE_NUM) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "there is no match seq ti clear");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t PutToRecvList(int32_t fd, uint32_t seq, const char *destFilePath, FileListener fileListener,
    int32_t sessionId)
{
    if (destFilePath == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "destFilePath is null");
        return SOFTBUS_ERR;
    }
    int index = 0;
    if (GetIdleIndexNode(&index) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetIdleIndexNode fail");
        return SOFTBUS_ERR;
    }
    g_recvFileInfo.sessionId = sessionId;
    g_recvFileInfo.recvFileInfo[index].index = index;
    g_recvFileInfo.recvFileInfo[index].seq = seq;
    g_recvFileInfo.recvFileInfo[index].fileFd = fd;
    g_recvFileInfo.recvFileInfo[index].fileStatus = NODE_BUSY;
    g_recvFileInfo.recvFileInfo[index].fileOffset = 0;
    g_recvFileInfo.recvFileInfo[index].timeOut = 0;
    if (memcpy_s(g_recvFileInfo.recvFileInfo[index].filePath, MAX_REMOTE_PATH_LEN,
        destFilePath, MAX_REMOTE_PATH_LEN) != EOK) {
        return SOFTBUS_ERR;
    }
    if (memcpy_s(&g_recvFileInfo.fileListener, sizeof(FileListener),
        &fileListener, sizeof(FileListener)) != EOK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UpdateRecvInfo(SingleFileInfo fileInfo)
{
    int index = fileInfo.index;
    if (index > MAX_RECV_FILE_NUM) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "fileInfo.index is large than MAX_RECV_FILE_NUM");
        return SOFTBUS_ERR;
    }
    g_recvFileInfo.sessionId = 0;
    g_recvFileInfo.recvFileInfo[index].index = fileInfo.index;
    g_recvFileInfo.recvFileInfo[index].seq = fileInfo.seq;
    g_recvFileInfo.recvFileInfo[index].fileFd = fileInfo.fileFd;
    g_recvFileInfo.recvFileInfo[index].fileStatus = fileInfo.fileStatus;
    g_recvFileInfo.recvFileInfo[index].fileOffset = fileInfo.fileOffset;
    g_recvFileInfo.recvFileInfo[index].timeOut = fileInfo.timeOut;
    if (memcpy_s(g_recvFileInfo.recvFileInfo[index].filePath, MAX_REMOTE_PATH_LEN, fileInfo.filePath,
        MAX_REMOTE_PATH_LEN) != EOK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static bool IsValidFileString(const char *str[], uint32_t fileNum, size_t maxLen)
{
    if (str == NULL || fileNum == 0) {
        return false;
    }
    for (uint32_t i = 0; i < fileNum; i++) {
        if (str[i] == NULL) {
            return false;
        }
        size_t len = strlen(str[i]);
        if (len == 0 || len > (maxLen - 1)) {
            return false;
        }
    }
    return true;
}

static int32_t FrameIndexToType(uint64_t index, uint64_t frameNumber)
{
#define FRAME_NUM_0 0
#define FRAME_NUM_1 1
#define FRAME_NUM_2 2
    if (index == FRAME_NUM_0) {
        return FILE_FIRST_FRAME;
    }

    if ((index == FRAME_NUM_1) && (frameNumber == FRAME_NUM_2)) {
        return FILE_ONLYONE_FRAME;
    }

    if (index == (frameNumber - 1)) {
        return FILE_LAST_FRAME;
    }

    return FILE_ONGOINE_FRAME;
}

static int32_t ProxyChannelSendFileStream(int32_t channelId, const char *data, uint32_t len, int32_t type)
{
#define FILE_RETRY_DELAY_TIME 100
#define FILE_RETRY_COUNT 3
    int32_t retry = FILE_RETRY_COUNT;
    int32_t ret;
    while (retry) {
        ret = ServerIpcSendMessage(channelId, CHANNEL_TYPE_PROXY, data, len, type);
        if (ret == SOFTBUS_CONNECTION_ERR_SENDQUEUE_FULL) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send queue full %d", ret);
            SoftBusSleepMs(FILE_RETRY_DELAY_TIME);
            retry--;
            continue;
        }
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send msg(%d): type=%d, ret=%d", channelId, type, ret);
        return ret;
    }
    return ret;
}

static int32_t FrameTypeToSessionType(int32_t type)
{
    switch (type) {
        case FILE_FIRST_FRAME:
            return TRANS_SESSION_FILE_FIRST_FRAME;
        case FILE_ONGOINE_FRAME:
            return TRANS_SESSION_FILE_ONGOINE_FRAME;
        case FILE_LAST_FRAME:
            return TRANS_SESSION_FILE_LAST_FRAME;
        case FILE_ONLYONE_FRAME:
            return TRANS_SESSION_FILE_ONLYONE_FRAME;
        case FILE_ALLFILE_SENT:
            return TRANS_SESSION_FILE_ALLFILE_SENT;
        default:
            return SOFTBUS_ERR;
    }
}

static void DoTransErrorCallBack()
{
    if (g_recvFileInfo.fileListener.recvListener.OnFileTransError != NULL) {
        g_recvFileInfo.fileListener.recvListener.OnFileTransError(g_recvFileInfo.sessionId);
    }
}

static void ProxyFileTransTimerProc(void)
{
#define FILE_TRANS_TIMEOUT 10
    if (SoftBusMutexLock(&g_recvFileInfo.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock file timer failed");
        return;
    }

    for (int32_t index = 0; index < MAX_RECV_FILE_NUM; index++) {
        int32_t status = g_recvFileInfo.recvFileInfo[index].fileStatus;
        int32_t timeOut = g_recvFileInfo.recvFileInfo[index].timeOut;
        if (status == NODE_BUSY) {
            if (timeOut >= FILE_TRANS_TIMEOUT) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file %s recv timeout",
                    g_recvFileInfo.recvFileInfo[index].filePath);
                g_recvFileInfo.recvFileInfo[index].fileStatus = NODE_ERR;
                g_recvFileInfo.recvFileInfo[index].timeOut = 0;
                close(g_recvFileInfo.recvFileInfo[index].fileFd);
                remove(g_recvFileInfo.recvFileInfo[index].filePath);
                DoTransErrorCallBack();
            } else {
                g_recvFileInfo.recvFileInfo[index].timeOut++;
            }
        }
    }

    SoftBusMutexUnlock(&g_recvFileInfo.lock);
    return;
}

static int32_t CheckAndGetFileSize(const char *sourceFile, uint64_t *fileSize)
{
    if ((sourceFile == NULL) || (fileSize == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "sourceFile or fileSize is null");
        return SOFTBUS_FILE_ERR;
    }
    struct stat statbuff;
    if (stat(sourceFile, &statbuff) < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "stat file fail");
        return SOFTBUS_FILE_ERR;
    } else {
        *fileSize = statbuff.st_size;
    }

    if (*fileSize > MAX_FILE_SIZE) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file is too large, filesize : %llu", *fileSize);
        return SOFTBUS_FILE_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t SendOneFrame(int32_t channelId, FileFrame fileFrame)
{
    if (fileFrame.data == NULL) {
        return SOFTBUS_ERR;
    }
    int32_t type = FrameTypeToSessionType(fileFrame.frameType);
    if (type == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Frame Type To Session Type fail %d", fileFrame.frameType);
        return SOFTBUS_ERR;
    }
    int32_t ret = ProxyChannelSendFileStream(channelId, (char *)fileFrame.data, fileFrame.frameLength, type);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "conn send buf fail %d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t FileToFrame(int32_t channelId, uint64_t frameNum, int32_t fd, const char *destFile, uint64_t fileSize)
{
#define SEND_DELAY_TIME 20
    FileFrame fileFrame;
    uint8_t *buffer = (uint8_t *)SoftBusCalloc(PROXY_MAX_PACKET_SIZE);
    if (buffer == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc send file buffer failed");
        return SOFTBUS_ERR;
    }
    uint64_t fileOffset = 0;
    uint64_t remainedSendSize = fileSize;
    uint64_t frameDataSize = PROXY_MAX_PACKET_SIZE - FRAME_DATA_SEQ_OFFSET;
    for (uint64_t index = 0; index < frameNum; index++) {
        fileFrame.frameType = FrameIndexToType(index, frameNum);
        fileFrame.data = buffer;
        if (memcpy_s(fileFrame.data, FRAME_DATA_SEQ_OFFSET, (char *)&channelId, FRAME_DATA_SEQ_OFFSET) != EOK) {
            SoftBusFree(fileFrame.data);
            return SOFTBUS_ERR;
        }
        if (index == 0) {
            uint32_t destFileNameSize = strlen(destFile);
            if (memcpy_s(fileFrame.data + FRAME_DATA_SEQ_OFFSET, destFileNameSize,
                destFile, destFileNameSize) != SOFTBUS_OK) {
                SoftBusFree(fileFrame.data);
                return SOFTBUS_ERR;
            }
            fileFrame.frameLength = FRAME_DATA_SEQ_OFFSET + destFileNameSize;
        } else {
            uint64_t readLength = (remainedSendSize < frameDataSize) ? remainedSendSize : frameDataSize;
            int32_t len = pread(fd, fileFrame.data + FRAME_DATA_SEQ_OFFSET, readLength, fileOffset);
            if (len >= 0) {
                fileOffset += readLength;
                fileFrame.frameLength = readLength + FRAME_DATA_SEQ_OFFSET;
                remainedSendSize -= readLength;
            } else {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pread src file failed");
                SoftBusFree(fileFrame.data);
                return SOFTBUS_ERR;
            }
        }
        if (SendOneFrame(channelId, fileFrame) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send one frame failed");
            SoftBusFree(fileFrame.data);
            return SOFTBUS_ERR;
        }
        memset_s(fileFrame.data, PROXY_MAX_PACKET_SIZE, 0, PROXY_MAX_PACKET_SIZE);
        SoftBusSleepMs(SEND_DELAY_TIME);
    }
    SoftBusFree(fileFrame.data);
    return SOFTBUS_OK;
}

static int32_t FileToFrameAndSendFile(int32_t channelId, const char *sourceFile, const char *destFile)
{
    uint64_t fileSize = 0;
    if (CheckAndGetFileSize(sourceFile, &fileSize) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "sourcefile size err");
        return SOFTBUS_FILE_ERR;
    }
    int32_t fd = open(sourceFile, O_RDONLY);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open file fail");
        return SOFTBUS_FILE_ERR;
    }
    if (PROXY_MAX_PACKET_SIZE <= FRAME_DATA_SEQ_OFFSET) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "stat file fail");
        return SOFTBUS_ERR;
    }
    uint64_t frameDataSize = PROXY_MAX_PACKET_SIZE - FRAME_DATA_SEQ_OFFSET;
    uint64_t frameNum = fileSize / frameDataSize;
    if ((fileSize % frameDataSize) != 0) {
        frameNum++;
    }

    /* add 1 means reserve frame to send destFile string */
    frameNum++;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "channelId:%d, fileName:%s, fileSize:%llu, frameNum:%llu",
        channelId, sourceFile, fileSize, frameNum);
    if (FileToFrame(channelId, frameNum, fd, destFile, fileSize) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "File To Frame fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static char *GetDestFilePath(FileFrame fileFrame)
{
    if (fileFrame.frameLength <= FRAME_DATA_SEQ_OFFSET) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CreateFileFromFrame framelength less then offset");
        return NULL;
    }

    int32_t filePathSize = fileFrame.frameLength - FRAME_DATA_SEQ_OFFSET + 1;
    if (filePathSize > MAX_REMOTE_PATH_LEN) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "filePath is too long");
        return NULL;
    }
    char *filePath = (char *)SoftBusCalloc(filePathSize);
    if (filePath == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "calloc filePath failed");
        return NULL;
    }
    if (memcpy_s(filePath, filePathSize, fileFrame.data + FRAME_DATA_SEQ_OFFSET,
        fileFrame.frameLength - FRAME_DATA_SEQ_OFFSET) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy_s failed");
        SoftBusFree(filePath);
        return NULL;
    }
    return filePath;
}

static int32_t GetDestFileFrameSeq(FileFrame fileFrame, uint32_t *seq)
{
    if (seq == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "seq is null");
        return SOFTBUS_ERR;
    }
    if (fileFrame.frameLength <= FRAME_DATA_SEQ_OFFSET) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CreateFileFromFrame framelength less then offset");
        return SOFTBUS_ERR;
    }

    if (memcpy_s(seq, FRAME_DATA_SEQ_OFFSET, fileFrame.data, FRAME_DATA_SEQ_OFFSET) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy_s failed");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static bool IsPathValid(char *filePath)
{
    if ((filePath == NULL) || (strlen(filePath) == 0) ||
        (strlen(filePath) > (MAX_REMOTE_PATH_LEN - 1))) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "filePath size is wrong");
        return false;
    }

    if (filePath[strlen(filePath) - 1] == PATH_SEPARATOR) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "filePath is end with '/' ");
        return false;
    }

    return true;
}

static int32_t CreateDestDir(const char *filePath)
{
    uint32_t len = (uint32_t)strlen(filePath);
    int32_t ret;
    char *tempPath = (char *)SoftBusCalloc(len + 1);
    if (tempPath == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "calloc tempPath failed");
        return SOFTBUS_ERR;
    }
    for (uint32_t i = 0; i < len; i++) {
        tempPath[i] = filePath[i];
        if (tempPath[i] != PATH_SEPARATOR) {
            continue;
        }
        if (access(tempPath, 0) == -1) {
            ret = mkdir(tempPath, DEFAULT_NEW_PATH_AUTHORITY);
            if (ret == -1 && errno != EEXIST) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "mkdir failed(%d)", errno);
                SoftBusFree(tempPath);
                return SOFTBUS_ERR;
            }
        }
    }

    SoftBusFree(tempPath);
    return SOFTBUS_OK;
}

static char *CreateFullRecvPath(const char *filePath, const char *recvRootDir)
{
    if ((filePath == NULL) || (recvRootDir == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "filePath is null or rootDir is null");
        return NULL;
    }

    int32_t rootDirLength = strlen(recvRootDir);
    int32_t filePathLength = strlen(filePath);
    bool isNeedAddSep = true;
    if (((filePathLength > 0) && (filePath[0] == PATH_SEPARATOR)) ||
        ((rootDirLength > 0) && (recvRootDir[rootDirLength - 1] == PATH_SEPARATOR))) {
        isNeedAddSep = false;
    }

    int32_t destFullPathLength = (isNeedAddSep) ? (rootDirLength + sizeof('/') + filePathLength) :
        (rootDirLength + filePathLength);
    char *recvFullPath = (char *)SoftBusCalloc(destFullPathLength + 1);
    if (recvFullPath == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "recvFullPath is null");
        return NULL;
    }

    int32_t ret;
    if (isNeedAddSep) {
        ret = sprintf_s(recvFullPath, destFullPathLength + 1, "%s%c%s", recvRootDir, PATH_SEPARATOR, filePath);
    } else {
        ret = sprintf_s(recvFullPath, destFullPathLength + 1, "%s%s", recvRootDir, filePath);
    }
    if (ret == -1) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create fullPath fail");
        SoftBusFree(recvFullPath);
        return NULL;
    }
    return recvFullPath;
}

static char *GetFileAbsPathAndSeq(FileFrame fileFrame, const char *rootDir, uint32_t *seq)
{
    if (seq == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "seq is null");
        return NULL;
    }

    if (GetDestFileFrameSeq(fileFrame, seq) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open destFile fail");
        return NULL;
    }

    char *destFilePath = GetDestFilePath(fileFrame);
    if (destFilePath == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetDestFilePath failed");
        return NULL;
    }

    char *fullRecvPath = CreateFullRecvPath(destFilePath, rootDir);
    if (IsPathValid(fullRecvPath) == false) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "destFilePath is invalid");
        SoftBusFree(destFilePath);
        SoftBusFree(fullRecvPath);
        return NULL;
    }

    SoftBusFree(destFilePath);
    return fullRecvPath;
}

static int32_t CreateFileFromFrame(int32_t sessionId, FileFrame fileFrame, FileListener fileListener)
{
    if (SoftBusMutexLock(&g_recvFileInfo.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock fileFromFrame fail");
        return SOFTBUS_ERR;
    }
    uint32_t seq = 0;

    char *fullRecvPath = GetFileAbsPathAndSeq(fileFrame, fileListener.rootDir, &seq);
    if (fullRecvPath == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "fullRecvPath is null");
        SoftBusMutexUnlock(&g_recvFileInfo.lock);
        return SOFTBUS_ERR;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "fullRecvPath %s, seq:%u", fullRecvPath, seq);
    if (CreateDestDir(fullRecvPath) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CreateDestFile failed");
        goto EXIT_ERR;
    }

    int32_t fd = open(fullRecvPath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open destFile fail");
        goto EXIT_ERR;
    }

    if (PutToRecvList(fd, seq, fullRecvPath, fileListener, sessionId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "put seq[%u] failed", seq);
        close(fd);
        remove(fullRecvPath);
        if (RemoveFromRecvListBySeq(seq) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remove from list failed");
        }
        goto EXIT_ERR;
    }

    if (fileListener.recvListener.OnReceiveFileStarted != NULL) {
        fileListener.recvListener.OnReceiveFileStarted(sessionId, fullRecvPath, 1);
    }
    SoftBusFree(fullRecvPath);
    SoftBusMutexUnlock(&g_recvFileInfo.lock);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "create file from frame success");
    return SOFTBUS_OK;
EXIT_ERR:
    SoftBusFree(fullRecvPath);
    SoftBusMutexUnlock(&g_recvFileInfo.lock);
    return SOFTBUS_ERR;
}

static int32_t ProcessOneFrame(FileFrame fileFrame, SingleFileInfo fileInfo, int32_t seq)
{
    int32_t frameLength = fileFrame.frameLength;
    if (fileFrame.frameLength <= FRAME_DATA_SEQ_OFFSET) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "WriteFrameToFile framelength less then offset");
        return SOFTBUS_ERR;
    }

    int32_t frameDataLength = frameLength - FRAME_DATA_SEQ_OFFSET;
    int32_t writeLength = pwrite(fileInfo.fileFd, fileFrame.data + FRAME_DATA_SEQ_OFFSET, frameDataLength,
        (uint64_t)fileInfo.fileOffset);
    if (writeLength < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pwrite file failed");
        return SOFTBUS_ERR;
    }
    fileInfo.fileOffset += (uint64_t)writeLength;

    if (fileInfo.fileOffset > MAX_FILE_SIZE) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file is too large, offset:%llu", fileInfo.fileOffset);
        return SOFTBUS_ERR;
    }
    if (UpdateRecvInfo(fileInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "UpdateRecvInfo fail");
        return SOFTBUS_ERR;
    }
    int32_t frameType = fileFrame.frameType;

    /* last frame */
    if ((frameType == FILE_LAST_FRAME) || (frameType == FILE_ONLYONE_FRAME)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "process last frame, seq:%d", seq);
        close(fileInfo.fileFd);
        if (RemoveFromRecvListBySeq(seq) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ClearRecvFileInfoBySeq fail");
            remove(fileInfo.filePath);
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t WriteFrameToFile(FileFrame fileFrame)
{
    if (SoftBusMutexLock(&g_recvFileInfo.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock write frame fail");
        return SOFTBUS_ERR;
    }
    uint32_t seq = 0;
    SingleFileInfo fileInfo = {0};
    if (GetDestFileFrameSeq(fileFrame, &seq) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open destFile fail");
        SoftBusMutexUnlock(&g_recvFileInfo.lock);
        return SOFTBUS_ERR;
    }

    if (GetRecvFileInfoBySeq(seq, &fileInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetFileFdBySeq fail");
        SoftBusMutexUnlock(&g_recvFileInfo.lock);
        return SOFTBUS_ERR;
    }

    if (fileInfo.fileStatus == NODE_ERR) {
        goto EXIT_ERR;
    }
    if (ProcessOneFrame(fileFrame, fileInfo, seq) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write one frame error");
        goto EXIT_ERR;
    }
    SoftBusMutexUnlock(&g_recvFileInfo.lock);
    return SOFTBUS_OK;
EXIT_ERR:
    close(fileInfo.fileFd);
    remove(fileInfo.filePath);
    if (RemoveFromRecvListBySeq(seq) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "WriteFrameToFile remove fail");
    }
    SoftBusMutexUnlock(&g_recvFileInfo.lock);
    return SOFTBUS_ERR;
}

int32_t ProcessFileFrameData(int32_t sessionId, FileListener fileListener, const char *data, int32_t len,
    int32_t type)
{
    int32_t ret;
    FileFrame oneFrame;
    oneFrame.frameType = type;
    oneFrame.frameLength = len;
    oneFrame.data = (uint8_t *)data;
    switch (oneFrame.frameType) {
        case FILE_FIRST_FRAME:
            ret = CreateFileFromFrame(sessionId, oneFrame, fileListener);
            if (ret != SOFTBUS_OK) {
                if (fileListener.recvListener.OnFileTransError != NULL) {
                    fileListener.recvListener.OnFileTransError(sessionId);
                }
            }
            break;
        case FILE_ONGOINE_FRAME:
        case FILE_ONLYONE_FRAME:
        case FILE_LAST_FRAME:
            ret = WriteFrameToFile(oneFrame);
            if (ret != SOFTBUS_OK) {
                if (fileListener.recvListener.OnFileTransError != NULL) {
                    fileListener.recvListener.OnFileTransError(sessionId);
                }
            }
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "frame type is invalid");
            return SOFTBUS_ERR;
    }
    return ret;
}

static int32_t FileListToBuffer(const char **destFile, uint32_t fileCnt, FileListBuffer *outbufferInfo)
{
    if (outbufferInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "outbufferInfo is NULL");
        return SOFTBUS_ERR;
    }
    outbufferInfo->buffer = NULL;
    outbufferInfo->bufferSize = 0;
    int32_t totalLength = 0;
    int32_t offset = 0;
    uint32_t index;
    for (index = 0; index < fileCnt; index++) {
        totalLength += strlen(destFile[index]);
    }

    int32_t fileNameSize = 0;
    int32_t indexSize  = sizeof(index);
    int32_t bufferSize = totalLength + (indexSize + sizeof(fileNameSize)) * fileCnt;
    uint8_t *buffer = (uint8_t *)SoftBusCalloc(bufferSize);
    if (buffer == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "calloc filelist failed");
        return SOFTBUS_ERR;
    }

    char byteBuff[sizeof(int32_t)] = {0};
    for (index = 0; index < fileCnt; index++) {
        if (IntToByte(index, byteBuff, indexSize) == false) {
            goto EXIT;
        }
        if (memcpy_s(buffer + offset, indexSize, byteBuff, indexSize) != EOK) {
            goto EXIT;
        }
        offset += indexSize;
        fileNameSize = strlen(destFile[index]);
        if (IntToByte(fileNameSize, byteBuff, indexSize) == false) {
            goto EXIT;
        }
        if (memcpy_s(buffer + offset, sizeof(fileNameSize), byteBuff, sizeof(fileNameSize)) != EOK) {
            goto EXIT;
        }
        offset += sizeof(fileNameSize);
        if (memcpy_s(buffer + offset, fileNameSize, destFile[index], fileNameSize) != EOK) {
            goto EXIT;
        }
        offset += fileNameSize;
    }

    outbufferInfo->buffer = buffer;
    outbufferInfo->bufferSize = offset;
    return SOFTBUS_OK;
EXIT:
    SoftBusFree(buffer);
    return SOFTBUS_ERR;
}

static int32_t BufferToFileList(FileListBuffer bufferInfo, char *firstFile, int32_t *fileCount)
{
    if ((bufferInfo.buffer == NULL) || (firstFile == NULL) || (fileCount == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "BufferToFileList input invalid");
        return SOFTBUS_ERR;
    }
    *fileCount = 0;
    uint8_t *buffer = bufferInfo.buffer;
    uint32_t offset = 0;
    int32_t count = 0;
    int32_t fileNameLength = 0;
    int32_t byteLen = sizeof(int32_t);
    char byteBuff[sizeof(int32_t)] = {0};
    while (offset < bufferInfo.bufferSize) {
        offset += sizeof(uint32_t);

        if (memcpy_s(byteBuff, byteLen, buffer + offset, byteLen) != EOK) {
            return SOFTBUS_ERR;
        }
        if (ByteToInt(byteBuff, byteLen, &fileNameLength) == false) {
            return SOFTBUS_ERR;
        }
        offset += byteLen;
        if ((fileNameLength < 0) || (fileNameLength > (int32_t)(bufferInfo.bufferSize - offset))) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "BufferToFileList invalid fileLength");
            return SOFTBUS_ERR;
        }
        /* only output first file path */
        if (count == 0) {
            if (memcpy_s(firstFile, fileNameLength, buffer + offset, fileNameLength) != EOK) {
                return SOFTBUS_ERR;
            }
        }
        offset += fileNameLength;
        count++;
    }

    *fileCount = count;
    return SOFTBUS_OK;
}

int32_t ProcessFileListData(int32_t sessionId, FileListener fileListener, const char *data, int32_t len)
{
    if (SoftBusMutexLock(&g_recvFileInfo.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock filelist data fail");
        return SOFTBUS_ERR;
    }

    FileListBuffer bufferInfo;
    char firtFilePath[MAX_REMOTE_PATH_LEN] = {0};
    int32_t fileCount = 0;
    bufferInfo.buffer = (uint8_t *)data;
    bufferInfo.bufferSize = (uint32_t)len;
    int32_t ret = BufferToFileList(bufferInfo, firtFilePath, &fileCount);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Buffer To File List failed");
        SoftBusMutexUnlock(&g_recvFileInfo.lock);
        return SOFTBUS_ERR;
    }

    char *fullRecvPath = CreateFullRecvPath(firtFilePath, fileListener.rootDir);
    if (IsPathValid(fullRecvPath) == false) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "fullRecvPath is invalid");
        SoftBusFree(fullRecvPath);
        SoftBusMutexUnlock(&g_recvFileInfo.lock);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "fullRecvPath:%s", fullRecvPath);

    if (fileListener.recvListener.OnReceiveFileFinished != NULL) {
        fileListener.recvListener.OnReceiveFileFinished(sessionId, fullRecvPath, fileCount);
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "Process File List Data success!!!");
    SoftBusFree(fullRecvPath);
    SoftBusMutexUnlock(&g_recvFileInfo.lock);
    return SOFTBUS_OK;
}

static int32_t SendFileList(int32_t channelId, const char **destFile, uint32_t fileCnt)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "SendFileList begin");
    FileListBuffer bufferInfo;
    int32_t ret = FileListToBuffer(destFile, fileCnt, &bufferInfo);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "FileListToBuffer failed");
        SoftBusFree(bufferInfo.buffer);
        return SOFTBUS_ERR;
    }

    /* send file list */
    int32_t type = TRANS_SESSION_FILE_ALLFILE_SENT;
    ret = ProxyChannelSendFileStream(channelId, (char *)bufferInfo.buffer, bufferInfo.bufferSize, type);
    if (ret < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "conn send buf fail %d", ret);
        SoftBusFree(bufferInfo.buffer);
        return ret;
    }

    SoftBusFree(bufferInfo.buffer);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "SendFileList success");

    return SOFTBUS_OK;
}

static int32_t SendSingleFile(int32_t channelId, const char *sourceFile, const char *destFile)
{
    if ((sourceFile == NULL) || (destFile == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "sourfile or dstfile is null");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send file[%s] begin, dest is :%s", sourceFile, destFile);

    int32_t ret;
    ret = FileToFrameAndSendFile(channelId, sourceFile, destFile);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "FileToFrameAndSendFile failed");
        return SOFTBUS_ERR;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send file[%s] success", sourceFile);

    return SOFTBUS_OK;
}

static int32_t ProxySendFile(int32_t channelId, const char *sFileList[], const char *dFileList[],
    uint32_t fileCnt)
{
    if (SoftBusMutexLock(&g_sendFileInfo.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }

    int32_t ret;
    if ((fileCnt == 0) || (fileCnt > MAX_FILE_NUM)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "sendfile arg filecnt[%d] error", fileCnt);
        SoftBusMutexUnlock(&g_sendFileInfo.lock);
        return SOFTBUS_ERR;
    }

    if (!IsValidFileString(sFileList, fileCnt, MAX_FILE_PATH_NAME_LEN) ||
        !IsValidFileString(dFileList, fileCnt, MAX_REMOTE_PATH_LEN)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "sendfile invalid arg input");
        SoftBusMutexUnlock(&g_sendFileInfo.lock);
        return SOFTBUS_ERR;
    }

    for (uint32_t index = 0; index < fileCnt; index++) {
        ret = SendSingleFile(channelId, sFileList[index], dFileList[index]);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendSingleFile %s, failed", sFileList[index]);
            SoftBusMutexUnlock(&g_sendFileInfo.lock);
            return SOFTBUS_ERR;
        }
    }

    ret = SendFileList(channelId, dFileList, fileCnt);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendFileList failed");
        SoftBusMutexUnlock(&g_sendFileInfo.lock);
        return SOFTBUS_ERR;
    }
    
    SoftBusMutexUnlock(&g_sendFileInfo.lock);
    return SOFTBUS_OK;
}

int32_t TransProxyChannelSendFile(int32_t channelId, const char *sFileList[], const char *dFileList[],
    uint32_t fileCnt)
{
    return ProxySendFile(channelId, sFileList, dFileList, fileCnt);
}
