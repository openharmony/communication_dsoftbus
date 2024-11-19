/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>

#include "client_trans_proxy_file_common.h"

#include "securec.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "trans_log.h"

#pragma pack(push, 1)
struct FileListItem {
    uint32_t index;
    uint32_t fileNameLength;
    char fileName[0];
};
#pragma pack(pop)

bool IsPathValid(char *filePath)
{
    if (filePath == NULL) {
        TRANS_LOGE(TRANS_FILE, "filePath is null");
        return false;
    }
    if ((strlen(filePath) == 0) || (strlen(filePath) > (MAX_FILE_PATH_NAME_LEN - 1))) {
        TRANS_LOGE(TRANS_FILE, "filePathSize is wrong. filePathSize=%{public}d", (int32_t)strlen(filePath));
        return false;
    }

    if (filePath[strlen(filePath) - 1] == PATH_SEPARATOR) {
        TRANS_LOGE(TRANS_FILE, "filePath is end with '/' ");
        return false;
    }
    return true;
}

int32_t GetAndCheckRealPath(const char *filePath, char *absPath)
{
    if ((filePath == NULL) || (absPath == NULL)) {
        TRANS_LOGE(TRANS_FILE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusRealPath(filePath, absPath) == NULL) {
        TRANS_LOGE(TRANS_FILE, "softbus realpath failed");
        return SOFTBUS_FILE_ERR;
    }

    int32_t pathLength = (int32_t)(strlen(absPath));
    if (pathLength > (MAX_FILE_PATH_NAME_LEN - 1)) {
        TRANS_LOGE(TRANS_FILE, "pathLength is too large. pathLength=%{public}d", pathLength);
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

bool CheckDestFilePathValid(const char *destFile)
{
    if (destFile == NULL) {
        TRANS_LOGE(TRANS_FILE, "destFile is null");
        return false;
    }
    int32_t len = (int32_t)(strlen(destFile));
    if ((len == 0) || (len > MAX_FILE_PATH_NAME_LEN)) {
        TRANS_LOGE(TRANS_FILE, "destFile path len is invalid");
        return false;
    }

    if (strstr(destFile, "..") != NULL) {
        TRANS_LOGE(TRANS_FILE, "dest path is not canonical form");
        return false;
    }
    return true;
}

int32_t FrameIndexToType(uint64_t index, uint64_t frameNumber)
{
    if (index == FRAME_NUM_0 || frameNumber == FRAME_NUM_0) {
        return TRANS_SESSION_FILE_FIRST_FRAME;
    }
    if ((index == FRAME_NUM_1) && (frameNumber == FRAME_NUM_2)) {
        return TRANS_SESSION_FILE_ONLYONE_FRAME;
    }
    if (index == (frameNumber - 1)) {
        return TRANS_SESSION_FILE_LAST_FRAME;
    }
    return TRANS_SESSION_FILE_ONGOINE_FRAME;
}

// crc校验表
static const unsigned char g_auchCRCHi[] = {
0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01,
0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80,
0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1,
0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01,
0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81,
0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01,
0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80,
0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01,
0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80,
0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
0x81, 0x40};

static const unsigned char g_auchCRCLo[] = {
0x00, 0xC0, 0xC1, 0x01, 0xC3, 0x03, 0x02, 0xC2, 0xC6, 0x06, 0x07, 0xC7, 0x05, 0xC5,
0xC4, 0x04, 0xCC, 0x0C, 0x0D, 0xCD, 0x0F, 0xCF, 0xCE, 0x0E, 0x0A, 0xCA, 0xCB, 0x0B,
0xC9, 0x09, 0x08, 0xC8, 0xD8, 0x18, 0x19, 0xD9, 0x1B, 0xDB, 0xDA, 0x1A, 0x1E, 0xDE,
0xDF, 0x1F, 0xDD, 0x1D, 0x1C, 0xDC, 0x14, 0xD4, 0xD5, 0x15, 0xD7, 0x17, 0x16, 0xD6,
0xD2, 0x12, 0x13, 0xD3, 0x11, 0xD1, 0xD0, 0x10, 0xF0, 0x30, 0x31, 0xF1, 0x33, 0xF3, 0xF2,
0x32, 0x36, 0xF6, 0xF7, 0x37, 0xF5, 0x35, 0x34, 0xF4, 0x3C, 0xFC, 0xFD, 0x3D, 0xFF, 0x3F,
0x3E, 0xFE, 0xFA, 0x3A, 0x3B, 0xFB, 0x39, 0xF9, 0xF8, 0x38, 0x28, 0xE8, 0xE9, 0x29, 0xEB,
0x2B, 0x2A, 0xEA, 0xEE, 0x2E, 0x2F, 0xEF, 0x2D, 0xED, 0xEC, 0x2C, 0xE4, 0x24, 0x25,
0xE5, 0x27, 0xE7, 0xE6, 0x26, 0x22, 0xE2, 0xE3, 0x23, 0xE1, 0x21, 0x20, 0xE0, 0xA0, 0x60,
0x61, 0xA1, 0x63, 0xA3, 0xA2, 0x62, 0x66, 0xA6, 0xA7, 0x67, 0xA5, 0x65, 0x64, 0xA4, 0x6C,
0xAC, 0xAD, 0x6D, 0xAF, 0x6F, 0x6E, 0xAE, 0xAA, 0x6A, 0x6B, 0xAB, 0x69, 0xA9, 0xA8,
0x68, 0x78, 0xB8, 0xB9, 0x79, 0xBB, 0x7B, 0x7A, 0xBA, 0xBE, 0x7E, 0x7F, 0xBF, 0x7D,
0xBD, 0xBC, 0x7C, 0xB4, 0x74, 0x75, 0xB5, 0x77, 0xB7, 0xB6, 0x76, 0x72, 0xB2, 0xB3, 0x73,
0xB1, 0x71, 0x70, 0xB0, 0x50, 0x90, 0x91, 0x51, 0x93, 0x53, 0x52, 0x92, 0x96, 0x56, 0x57,
0x97, 0x55, 0x95, 0x94, 0x54, 0x9C, 0x5C, 0x5D, 0x9D, 0x5F, 0x9F, 0x9E, 0x5E, 0x5A, 0x9A,
0x9B, 0x5B, 0x99, 0x59, 0x58, 0x98, 0x88, 0x48, 0x49, 0x89, 0x4B, 0x8B, 0x8A, 0x4A, 0x4E,
0x8E, 0x8F, 0x4F, 0x8D, 0x4D, 0x4C, 0x8C, 0x44, 0x84, 0x85, 0x45, 0x87, 0x47, 0x46, 0x86,
0x82, 0x42, 0x43, 0x83, 0x41, 0x81, 0x80, 0x40};

// 校验函数
uint16_t RTU_CRC(const unsigned char *puchMsg, uint16_t usDataLen)
{
    unsigned char uchCRCHi = 0xFF;
    unsigned char uchCRCLo = 0xFF;
    uint16_t dataLen = usDataLen;
    const uint8_t *data = puchMsg;
    while (dataLen--) {
        unsigned char uIndex = uchCRCLo ^ (*data++);
        uchCRCLo = uchCRCHi ^ g_auchCRCHi[uIndex];
        uchCRCHi = g_auchCRCLo[uIndex];
    }
    return ((uchCRCHi << BIT_BYTE_NUM) | uchCRCLo);
}

const char *TransGetFileName(const char *path)
{
    if (path == NULL) {
        TRANS_LOGE(TRANS_FILE, "input is NULL!");
        return NULL;
    }
    size_t pathLength = strlen(path);
    if (pathLength == 0) {
        TRANS_LOGE(TRANS_FILE, "input length is 0!");
        return NULL;
    }
    if (path[pathLength - 1] == SOFTBUS_PATH_SEPRATOR) {
        TRANS_LOGE(TRANS_FILE, "input is dir path!");
        return NULL;
    }

    int i;
    for (i = (int)(pathLength - 1); i >= 0; i--) {
        if (path[i] == SOFTBUS_PATH_SEPRATOR) {
            i++;
            break;
        }
        if (i == 0) {
            break;
        }
    }
    return path + i;
}

int32_t FileListToBuffer(const char **destFile, uint32_t fileCnt, FileListBuffer *outbufferInfo)
{
    if (destFile == NULL || outbufferInfo == NULL || fileCnt == 0) {
        TRANS_LOGE(TRANS_FILE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t errCode = SOFTBUS_OK;
    uint32_t totalLength = 0;
    uint32_t offset = 0;
    for (uint32_t i = 0; i < fileCnt; i++) {
        size_t fileNameLength = strlen(destFile[i]);
        if (fileNameLength == 0 || fileNameLength > MAX_FILE_PATH_NAME_LEN) {
            TRANS_LOGE(TRANS_FILE, "bad file name at index=%{public}" PRIu32, i);
            return SOFTBUS_INVALID_PARAM;
        } else {
            totalLength += fileNameLength;
        }
    }

    size_t bufferSize = totalLength + (sizeof(struct FileListItem) * fileCnt);
    uint8_t *buffer = (uint8_t *)SoftBusCalloc(bufferSize);
    if (buffer == NULL) {
        TRANS_LOGE(TRANS_FILE, "calloc filelist failed");
        return SOFTBUS_MALLOC_ERR;
    }

    for (uint32_t index = 0; index < fileCnt; index++) {
        uint32_t fileNameSize = strlen(destFile[index]);
        struct FileListItem *fileItem = (struct FileListItem *)(buffer + offset);
        fileItem->index = htonl(index);
        fileItem->fileNameLength = htonl(fileNameSize);
        offset += sizeof(struct FileListItem);

        // note: no \0 here
        if (memcpy_s(fileItem->fileName, bufferSize - offset, destFile[index], fileNameSize) != EOK) {
            TRANS_LOGE(TRANS_FILE, "copy file name failed!");
            errCode = SOFTBUS_MEM_ERR;
            break;
        }

        offset += fileNameSize;
    }

    if (errCode != SOFTBUS_OK) {
        SoftBusFree(buffer);
        return errCode;
    }

    outbufferInfo->buffer = buffer;
    outbufferInfo->bufferSize = offset;
    return SOFTBUS_OK;
}

char *BufferToFileList(uint8_t *buffer, uint32_t bufferSize, int32_t *fileCount)
{
    if ((buffer == NULL) || (fileCount == NULL) || bufferSize < sizeof(struct FileListItem)) {
        TRANS_LOGE(TRANS_FILE, "input invalid");
        return NULL;
    }
    char *firstFile = (char *)SoftBusCalloc(MAX_FILE_PATH_NAME_LEN + 1);
    if (firstFile == NULL) {
        TRANS_LOGE(TRANS_FILE, "calloc fail");
        return NULL;
    }
    uint32_t offset = 0;
    int32_t count = 0;
    while (offset < bufferSize - sizeof(struct FileListItem)) {
        const struct FileListItem *fileListItem = (const struct FileListItem *)(buffer + offset);
        offset += sizeof(struct FileListItem);

        uint32_t fileNameLength = ntohl(fileListItem->fileNameLength);
        if (fileNameLength > bufferSize - offset || fileNameLength > MAX_FILE_PATH_NAME_LEN) {
            TRANS_LOGE(TRANS_FILE, "invalid fileLength");
            SoftBusFree(firstFile);
            return NULL;
        }
        /* only output first file path */
        if (count == 0) {
            // note: no \0 in buffer
            if (memcpy_s(firstFile, MAX_FILE_PATH_NAME_LEN, fileListItem->fileName, fileNameLength) != EOK) {
                SoftBusFree(firstFile);
                return NULL;
            }
        }
        offset += fileNameLength;
        count++;
    }

    *fileCount = count;
    return firstFile;
}

int32_t FileLock(int32_t fd, int32_t type, bool isBlock)
{
    if (fd < 0) {
        TRANS_LOGE(TRANS_FILE, "[FileLock] invalid file handle");
        return SOFTBUS_INVALID_PARAM;
    }
    struct flock fl = {0};
    fl.l_type = (short)(type == SOFTBUS_F_RDLCK ? F_RDLCK : F_WRLCK);
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    int32_t ret = fcntl(fd, isBlock ? F_SETLKW : F_SETLK, &fl);
    if (ret != 0 && !isBlock) {
        TRANS_LOGE(TRANS_FILE, "lock file is blocked, file busy errno=%{public}d", errno);
        return SOFTBUS_FILE_BUSY;
    }
    TRANS_LOGE(TRANS_FILE, "file locked! ret=%{public}d, errno=%{public}d", ret, errno);
    return SOFTBUS_OK;
}

int32_t TryFileLock(int32_t fd, int32_t type, int32_t retryTimes)
{
#define TRY_LOCK_WAIT_TIME 100
    int32_t errCode;
    while (retryTimes > 0) {
        errCode = FileLock(fd, type, false);
        if (errCode == SOFTBUS_OK) {
            return SOFTBUS_OK;
        } else if (errCode == SOFTBUS_FILE_BUSY) {
            --retryTimes;
            SoftBusSleepMs(TRY_LOCK_WAIT_TIME);
            continue;
        } else {
            return SOFTBUS_FILE_ERR;
        }
    }
    return SOFTBUS_FILE_BUSY;
}

int32_t FileUnLock(int32_t fd)
{
    if (fd < 0) {
        TRANS_LOGE(TRANS_FILE, "[FileUnLock] invalid file handle");
        return SOFTBUS_OK;
    }
    struct flock fl = {0};
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    if (fcntl(fd, F_SETLK, &fl) < 0) {
        TRANS_LOGE(TRANS_FILE, "unLock file failed, errno=%{public}d", errno);
        return SOFTBUS_FILE_ERR;
    }
    TRANS_LOGE(TRANS_FILE, "unLock file success");
    return SOFTBUS_OK;
}