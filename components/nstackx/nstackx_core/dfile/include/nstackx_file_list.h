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

#ifndef NSTACKX_FILE_LIST_H
#define NSTACKX_FILE_LIST_H

#include <stdint.h>
#include <stdio.h>
#include "nstackx_dfile.h"
#include "nstackx_list.h"
#ifdef __cplusplus
extern "C" {
#endif

#define NSTACKX_FLAGS_FILE_NAME_ACK           0x01
#define NSTACKX_FLAGS_FILE_NAME_RECEIVED      0x02
#define NSTACKX_FLAGS_FILE_RECEIVE_SUCCESS    0x04
#define NSTACKX_FLAGS_FILE_RECEIVE_FAIL       0x08
#define NSTACKX_FLAGS_FILE_SEND_SUCCESS       0x10
#define NSTACKX_FLAGS_LAST_BLOCK_RECEIVED     0x20

#define NSTACKX_FLAGS_USER_DATA_ACK           0x4

#define NOTICE_FILE_NAME_TYPE 0
#define NOTICE_FULL_FILE_NAME_TYPE 1
#define PATH_TYPE_PACKED_LEN 4

typedef struct {
    uint16_t fileId;
    uint8_t flags;
    char fileName[NSTACKX_MAX_REMOTE_PATH_LEN];
    char *fullFileName;
    char *remotePath; /* just usefully for sender */
    uint64_t fileSize;
    uint64_t startOffset;
} FileListEntry;

typedef struct FileList {
    FileListEntry *list;
    char *userData;
    uint32_t num;
    uint8_t userDataFlag;
    uint8_t noticeFileNameType; /* just usefully for sender */
    uint16_t pathType;
    uint8_t *packedUserData; /* just usefully for sender */
    uint16_t packedUserDataLen; /* just usefully for sender */
    uint8_t tarFlag;
    uint8_t smallFlag;
    uint8_t noSyncFlag;
    char *tarFile;
    uint8_t  vtransFlag;
    uint8_t  isFirstVtransOfFile;
    uint16_t vtransRealTransId;
    uint16_t vtransTotalNum;
    uint16_t vtransRealFileId;
    uint16_t vtransTotalFileNum;
    uint64_t vtransTotalFileSize;
} FileList;

typedef struct {
    List list;
    char **files; /* file name */
    char **remotePath; /* remote file path */
    uint64_t startOffset[NSTACKX_DFILE_MAX_FILE_NUM];
    uint64_t fileSize[NSTACKX_DFILE_MAX_FILE_NUM];
    char *userData;
    uint32_t fileNum;
    uint8_t tarFlag;
    uint8_t smallFlag;
    uint8_t noSyncFlag;
    char *tarFile;
    uint8_t noticeFileNameType;
    uint16_t pathType;
    uint8_t  vtransFlag;
    uint16_t vtransRealTransId;
    uint16_t vtransTotalNum;
    uint16_t vtransTotalFileNum;
    uint16_t vtransRealFileId;
    uint64_t vtransTotalFileSize;
} FileListInfo;

typedef struct {
    const char **files; /* file name */
    const char **remotePath; /* remote file path */
    uint64_t *startOffset;
    uint64_t *fileSize;
    const char *userData;
    uint32_t fileNum;
    uint8_t tarFlag;
} FileListPara;

#define NEW_FILE_LIST_PARA(_files, _remotePath, _fileNum, _userData, _tarFlag, _startOffset, _fileSize) \
{ \
    .files = (_files), \
    .remotePath = (_remotePath), \
    .fileNum = (_fileNum), \
    .userData = (_userData), \
    .tarFlag = (_tarFlag), \
    .startOffset = (_startOffset), \
    .fileSize = (_fileSize), \
}

typedef struct {
    uint16_t fileId;
    const uint8_t *fileName;
    size_t fileNameLength;
    uint64_t fileSize;
    uint64_t startOffset;
} FilePara;
static inline char *FileListGetRemotePath(FileList *fileList, uint16_t fileId)
{
    return (fileList)->list[(fileId) - 1].remotePath;
}

static inline char *FileListGetFileName(FileList *fileList, uint16_t fileId)
{
    return (fileList)->list[(fileId) - 1].fileName;
}

static inline uint64_t FileListGetFileSize(FileList *fileList, uint16_t fileId)
{
    return (fileList)->list[(fileId) - 1].fileSize;
}

static inline uint16_t FileListGetNum(const FileList *fileList)
{
    return (uint16_t)fileList->num;
}

static inline uint16_t FileListGetPathType(FileList *fileList)
{
    return (fileList)->pathType;
}

void FileListSetFileNameAcked(FileList *fileList, uint16_t fileId);
uint8_t FileListGetFileNameAcked(FileList *fileList, uint16_t fileId);

static inline uint8_t FileListGetFileNameReceived(FileList *fileList, uint16_t fileId)
{
    return (fileList)->list[(fileId) - 1].flags & NSTACKX_FLAGS_FILE_NAME_RECEIVED;
}

static inline void FileListSetLastBlockReceived(FileList *fileList, uint16_t fileId)
{
    (fileList)->list[(fileId) - 1].flags |= NSTACKX_FLAGS_LAST_BLOCK_RECEIVED;
    return;
}

static inline uint8_t FileListGetLastBlockReceived(FileList *fileList, uint16_t fileId)
{
    return (fileList)->list[(fileId) - 1].flags & NSTACKX_FLAGS_LAST_BLOCK_RECEIVED;
}

static inline void FileListSetFileReceiveSuccess(FileList *fileList, uint16_t fileId)
{
    (fileList)->list[(fileId) - 1].flags |= NSTACKX_FLAGS_FILE_RECEIVE_SUCCESS;
    return;
}

static inline void FileListSetFileReceiveFail(FileList *fileList, uint16_t fileId)
{
    (fileList)->list[(fileId) - 1].flags |= NSTACKX_FLAGS_FILE_RECEIVE_FAIL;
    return;
}

static inline void FileListSetFileSendSuccess(FileList *fileList, uint16_t fileId)
{
    (fileList)->list[(fileId) - 1].flags |= NSTACKX_FLAGS_FILE_SEND_SUCCESS;
    return;
}

uint8_t FileListAllFileNameAcked(const FileList *fileList);
uint8_t FileListAllFileNameReceived(const FileList *fileList);
uint8_t FileListAllFileReceived(const FileList *fileList);
int32_t FileListSetSendFileList(FileList *fileList, FileListInfo *fileListInfo);
int32_t FileListSetRecvFileList(FileList *fileList, const char *files[], uint32_t fileNum);
/* To get all the file names. */
void FileListGetNames(FileList *fileList, char *files[], uint32_t *fileNum, uint8_t isFullFile);
/* To get all the files that received successfully, which may be less than FileListGetNames() */
void FileListGetReceivedFiles(FileList *fileList, char *files[], uint32_t *fileNum);
/* To get all the files that sent successfully, which may be less than FileListGetNames() */
void FileListGetSentFiles(FileList *fileList, char *files[], uint32_t *fileNum);
void FileListGetReceivedFileIdList(FileList *fileList, uint16_t fileIdList[], uint32_t *fileNum);

int32_t FileListSetNum(FileList *fileList, uint32_t fileNum);
int32_t FileListAddFile(FileList *fileList, uint16_t fileId, const uint8_t *fileName, size_t fileNameLength,
                        uint64_t fileSize);
int32_t FileListAddUserData(FileList *fileList, const uint8_t *userData, size_t userDataLength, uint8_t flag);
int32_t FileListAddExtraInfo(FileList *fileList, uint16_t pathType, uint8_t noticeFileNameType, char *userData);
int32_t FileListRenameFile(FileList *fileList, uint16_t fileId, const char *newFileName);
FileList *FileListCreate(void);
void FileListDestroy(FileList *fileList);
uint64_t GetFilesTotalBytes(FileList *fileList);
FileListInfo *CreateFileListInfo(FileListPara *fileListPara);
void DestroyFileListInfo(FileListInfo *fileListInfo);
#ifdef __cplusplus
}
#endif

#endif /* #ifndef NSTACKX_FILE_LIST_H */
