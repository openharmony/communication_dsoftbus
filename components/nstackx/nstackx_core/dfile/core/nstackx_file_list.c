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

#include "nstackx_file_list.h"
#include "nstackx_error.h"
#include "nstackx_util.h"
#include "nstackx_dfile_log.h"
#include "nstackx_dfile_frame.h"
#include "securec.h"

#define TAG "nStackXDFile"

uint8_t FileListAllFileNameAcked(const FileList *fileList)
{
    uint32_t i;
    if ((fileList->userDataFlag & NSTACKX_DFILE_HEADER_FRAME_USER_DATA_FLAG) &&
        !(fileList->userDataFlag & NSTACKX_FLAGS_USER_DATA_ACK)) {
        DFILE_LOGI(TAG, "user data not acked");
        return NSTACKX_FALSE;
    }

    if (fileList->tarFlag == NSTACKX_TRUE) {
        if (!(fileList->list[0].flags & NSTACKX_FLAGS_FILE_NAME_ACK)) {
            DFILE_LOGI(TAG, "file name 1 is not ACKED yet");
            return NSTACKX_FALSE;
        } else {
            return NSTACKX_TRUE;
        }
    }

    for (i = 0; i < fileList->num; i++) {
        if (!(fileList->list[i].flags & NSTACKX_FLAGS_FILE_NAME_ACK)) {
            DFILE_LOGI(TAG, "file name id %u is not ACKED yet", i + 1);
            return NSTACKX_FALSE;
        }
    }

    return NSTACKX_TRUE;
}

uint8_t FileListAllFileNameReceived(const FileList *fileList)
{
    uint32_t i;

    if (!fileList->num) {
        return NSTACKX_FALSE;
    }

    if ((fileList->userDataFlag & NSTACKX_DFILE_HEADER_FRAME_USER_DATA_FLAG) &&
        !(fileList->userDataFlag & NSTACKX_FLAGS_FILE_NAME_RECEIVED)) {
        return NSTACKX_FALSE;
    }

    if (fileList->tarFlag == NSTACKX_TRUE) {
        if (!(fileList->list[0].flags & NSTACKX_FLAGS_FILE_NAME_RECEIVED)) {
            DFILE_LOGI(TAG, "file name id 1 is not RECEIVED yet");
            return NSTACKX_FALSE;
        } else {
            return NSTACKX_TRUE;
        }
    }

    for (i = 0; i < fileList->num; i++) {
        if (!(fileList->list[i].flags & NSTACKX_FLAGS_FILE_NAME_RECEIVED)) {
            DFILE_LOGI(TAG, "file name id %u is not RECEIVED yet", i + 1);
            return NSTACKX_FALSE;
        }
    }

    return NSTACKX_TRUE;
}

uint8_t FileListAllFileReceived(const FileList *fileList)
{
    uint32_t i;

    if (fileList->tarFlag == NSTACKX_TRUE) {
        if (!(fileList->list[0].flags & NSTACKX_FLAGS_FILE_RECEIVE_SUCCESS)) {
            return NSTACKX_FALSE;
        } else {
            return NSTACKX_TRUE;
        }
    }

    for (i = 0; i < fileList->num; i++) {
        if (!(fileList->list[i].flags & NSTACKX_FLAGS_FILE_RECEIVE_SUCCESS)) {
            return NSTACKX_FALSE;
        }
    }

    return NSTACKX_TRUE;
}

int32_t FileListSetSendFileList(FileList *fileList, FileListInfo *fileListInfo)
{
    uint16_t i;
    FileListEntry *fileListEntry = NULL;
    FileListEntry *entryList = NULL;
    int32_t ret;

    if (fileListInfo->files == NULL || fileListInfo->fileNum == 0 ||
        fileListInfo->fileNum > NSTACKX_DFILE_MAX_FILE_NUM) {
        DFILE_LOGE(TAG, "invalid input");
        return NSTACKX_EINVAL;
    }

    if (fileList->list != NULL) {
        DFILE_LOGE(TAG, "invalid fileList->list");
        return NSTACKX_EFAILED;
    }

    entryList = calloc(fileListInfo->fileNum, sizeof(FileListEntry));
    if (entryList == NULL) {
        DFILE_LOGE(TAG, "entryList calloc NULL");
        return NSTACKX_ENOMEM;
    }

    for (i = 0; i < fileListInfo->fileNum; i++) {
        fileListEntry = &entryList[i];
        /* Reuse the input memory. */
        fileListEntry->fullFileName = fileListInfo->files[i];
        if (fileListInfo->remotePath != NULL) {
            fileListEntry->remotePath = fileListInfo->remotePath[i];
        }
        ret = GetFileName(fileListEntry->fullFileName, fileListEntry->fileName, sizeof(fileListEntry->fileName));
        if (ret != NSTACKX_EOK) {
            DFILE_LOGE(TAG, "GetFileName error: %d", ret);
            goto L_FIN;
        }
        ret = GetTargetFileSize(fileListEntry->fullFileName, &fileListEntry->fileSize);
        if ((ret != NSTACKX_EOK) || (fileListEntry->fileSize > NSTACKX_MAX_FILE_SIZE)) {
            DFILE_LOGE(TAG, "GetTargetFileSize error: %d", ret);
            goto L_FIN;
        }
        if (fileListInfo->vtransFlag) {
            fileListEntry->startOffset = fileListInfo->startOffset[i];
            fileListEntry->fileSize = fileListInfo->fileSize[i];
        }
        fileListEntry->fileId = i + 1;
    }

    fileList->list = entryList;
    fileList->num = fileListInfo->fileNum;
    return NSTACKX_EOK;

L_FIN:
    /* Something wrong, clear file list */
    free(entryList);
    entryList = NULL;
    return ret;
}

int32_t FileListSetNum(FileList *fileList, uint32_t fileNum)
{
    if (fileNum == 0 || fileNum > NSTACKX_DFILE_MAX_FILE_NUM) {
        return NSTACKX_EINVAL;
    }

    if (fileList->list != NULL) {
        return NSTACKX_EOK;
    }

    fileList->list = calloc(fileNum, sizeof(FileListEntry));
    if (fileList->list == NULL) {
        return NSTACKX_ENOMEM;
    }
    fileList->num = fileNum;
    return NSTACKX_EOK;
}

int32_t FileListAddFile(FileList *fileList, uint16_t fileId, const uint8_t *fileName, size_t fileNameLength,
                        uint64_t fileSize)
{
    FileListEntry *fileListEntry = NULL;

    if (fileList->list == NULL || fileList->num == 0) {
        return NSTACKX_EINVAL;
    }

    if (fileId == 0 || fileId > fileList->num) {
        return NSTACKX_EINVAL;
    }

    if (fileNameLength + 1 > NSTACKX_MAX_REMOTE_PATH_LEN) {
        return NSTACKX_EINVAL;
    }

    if (fileSize > NSTACKX_MAX_FILE_SIZE) {
        return NSTACKX_EINVAL;
    }

    fileListEntry = &fileList->list[fileId - 1];

    if (fileListEntry->flags & NSTACKX_FLAGS_FILE_NAME_RECEIVED) {
        /* duplicate frame */
        return NSTACKX_EOK;
    }

    if (memcpy_s(fileListEntry->fileName, sizeof(fileListEntry->fileName) - 1, fileName, fileNameLength) != EOK) {
        return NSTACKX_EFAILED;
    }
    fileListEntry->fileId = fileId;
    fileListEntry->fileSize = fileSize;
    fileListEntry->flags |= NSTACKX_FLAGS_FILE_NAME_RECEIVED;
    if (fileSize == 0) {
        fileListEntry->flags |= NSTACKX_FLAGS_LAST_BLOCK_RECEIVED;
    }

    return NSTACKX_EOK;
}

static int32_t ParsePackedDFileUserData(const uint8_t *buf, size_t userDataLength, uint16_t *pathType, char **userData,
                                        uint8_t flag)
{
    char *validUserData = NULL;
    uint16_t userDataStrLen;
    const UserDataUnit *userDataUnit = NULL;
    if (userDataLength < sizeof(UserDataUnit)) {
        DFILE_LOGE(TAG, "userDataLength is too small");
        return NSTACKX_EFAILED;
    }
    userDataUnit = (UserDataUnit *)buf;
    *pathType = userDataUnit->pathType;
    if (*pathType == 0) {
        DFILE_LOGE(TAG, "path type is 0");
        return NSTACKX_EFAILED;
    }
    if (!(flag & NSTACKX_DFILE_HEADER_FRAME_USER_DATA_FLAG)) {
        return NSTACKX_EOK;
    }
    userDataStrLen = (uint16_t)(userDataLength - sizeof(UserDataUnit));
    validUserData = (char *)calloc(userDataStrLen + 1, 1);
    if (validUserData == NULL) {
        return NSTACKX_EFAILED;
    }
    if (userDataStrLen > 0 &&
        memcpy_s(validUserData, userDataStrLen + 1, userDataUnit->userData, userDataStrLen) != EOK) {
        free(validUserData);
        return NSTACKX_EFAILED;
    }
    *userData = validUserData;
    return NSTACKX_EOK;
}

int32_t FileListAddUserData(FileList *fileList, const uint8_t *userData, size_t userDataLength, uint8_t flag)
{
    if (fileList->userDataFlag & NSTACKX_FLAGS_FILE_NAME_RECEIVED) {
        /* duplicate frame */
        return NSTACKX_EOK;
    }
    if (flag & NSTACKX_DFILE_HEADER_FRAME_PATH_TYPE_FLAG) {
        if (ParsePackedDFileUserData(userData, userDataLength, &fileList->pathType, &fileList->userData, flag) !=
            NSTACKX_EOK) {
            DFILE_LOGE(TAG, "ParsePackedDFileUserData failed");
        }
    } else if (flag & NSTACKX_DFILE_HEADER_FRAME_USER_DATA_FLAG) {
        fileList->userData = calloc(1, userDataLength + 1);
        if (fileList->userData == NULL) {
            return NSTACKX_ENOMEM;
        }
        if (userDataLength) {
            if (memcpy_s(fileList->userData, userDataLength + 1, userData, userDataLength) != EOK) {
                free(fileList->userData);
                fileList->userData = NULL;
                return NSTACKX_EFAILED;
            }
        }
    } else {
        DFILE_LOGE(TAG, "invalid flag %2X", flag);
        return NSTACKX_EFAILED;
    }
    fileList->userDataFlag |= NSTACKX_FLAGS_FILE_NAME_RECEIVED;
    return NSTACKX_EOK;
}

void FileListGetNames(FileList *fileList, char *files[], uint32_t *fileNum, uint8_t fileNameType)
{
    uint32_t i;

    for (i = 0; i < fileList->num && i < *fileNum; i++) {
        /* Soft copy */
        if (fileList->tarFlag == NSTACKX_TRUE) {
            files[i] = fileList->tarFile;
            *fileNum = 1;
            return;
        }
        if (fileNameType == NOTICE_FULL_FILE_NAME_TYPE) {
            files[i] = fileList->list[i].fullFileName;
        } else if (fileNameType == NOTICE_FILE_NAME_TYPE) {
            files[i] = fileList->list[i].fileName;
        } else {
            DFILE_LOGE(TAG, "invalid fileName type %u", fileNameType);
            break;
        }
    }
    *fileNum = i;
}

void FileListGetReceivedFileIdList(FileList *fileList, uint16_t fileIdList[], uint32_t *fileNum)
{
    uint32_t i;
    uint32_t count = 0;

    for (i = 0; i < fileList->num && i < *fileNum; i++) {
        if (fileList->list[i].flags & NSTACKX_FLAGS_FILE_RECEIVE_SUCCESS) {
            fileIdList[count] = fileList->list[i].fileId;
            count++;
        }
    }
    *fileNum = count;
}

static void FileListGetFilesByFlag(FileList *fileList, uint8_t flags, char *files[], uint32_t *fileNum,
                                   uint8_t fileNameType)
{
    uint32_t i;
    uint32_t count = 0;

    for (i = 0; i < fileList->num && i < *fileNum; i++) {
        if (fileList->list[i].flags & flags) {
            if (fileList->tarFlag == NSTACKX_TRUE) {
                files[count] = fileList->tarFile;
                count++;
                break;
            }
            if (fileNameType == NOTICE_FULL_FILE_NAME_TYPE) {
                files[count] = fileList->list[i].fullFileName;
                count++;
            } else if (fileNameType == NOTICE_FILE_NAME_TYPE) {
                files[count] = fileList->list[i].fileName;
                count++;
            } else {
                DFILE_LOGE(TAG, "invalid fileName type %u", fileNameType);
                break;
            }
        } else {
            DFILE_LOGE(TAG, "the %uth file is not with target flag %2X", i, flags);
        }
    }
    *fileNum = count;
}

void FileListGetReceivedFiles(FileList *fileList, char *files[], uint32_t *fileNum)
{
    FileListGetFilesByFlag(fileList, NSTACKX_FLAGS_FILE_RECEIVE_SUCCESS, files, fileNum, NOTICE_FILE_NAME_TYPE);
}

void FileListGetSentFiles(FileList *fileList, char *files[], uint32_t *fileNum)
{
    FileListGetFilesByFlag(fileList, NSTACKX_FLAGS_FILE_SEND_SUCCESS, files, fileNum, fileList->noticeFileNameType);
}

void FileListSetFileNameAcked(FileList *fileList, uint16_t fileId)
{
    if (fileId == 1 || fileId == fileList->num) {
        DFILE_LOGI(TAG, "set file id: %u acked", fileId);
    }
    if (fileId == 0) {
        fileList->userDataFlag |= NSTACKX_FLAGS_USER_DATA_ACK;
    } else {
        (fileList)->list[(fileId) - 1].flags |= NSTACKX_FLAGS_FILE_NAME_ACK;
    }
}

uint8_t FileListGetFileNameAcked(FileList *fileList, uint16_t fileId)
{
    if (fileId == 0) {
        return (fileList->userDataFlag & NSTACKX_FLAGS_USER_DATA_ACK);
    } else {
        return ((fileList)->list[(fileId) - 1].flags & NSTACKX_FLAGS_FILE_NAME_ACK);
    }
}

FileList *FileListCreate(void)
{
    FileList *fileList = NULL;

    fileList = malloc(sizeof(FileList));
    if (fileList == NULL) {
        return NULL;
    }
    (void)memset_s(fileList, sizeof(FileList), 0, sizeof(FileList));

    return fileList;
}

void FileListDestroy(FileList *fileList)
{
    uint32_t i;
    FileListEntry *fileListEntry = NULL;
    if (fileList->userData != NULL) {
        free(fileList->userData);
        fileList->userData = NULL;
    }

    if (fileList->packedUserData != NULL) {
        free(fileList->packedUserData);
        fileList->packedUserData = NULL;
    }

    if (fileList->tarFile != NULL) {
        free(fileList->tarFile);
        fileList->tarFile = NULL;
    }

    for (i = 0; i < fileList->num; i++) {
        fileListEntry = &fileList->list[i];
        free(fileListEntry->fullFileName);
        fileListEntry->fullFileName = NULL;
        if (fileListEntry->remotePath != NULL) {
            free(fileListEntry->remotePath);
            fileListEntry->remotePath = NULL;
        }
    }
    free(fileList->list);
    free(fileList);
    fileList = NULL;
}

uint64_t GetFilesTotalBytes(FileList *fileList)
{
    uint64_t ret = 0;
    uint32_t i;
    if (fileList == NULL) {
        return ret;
    }
    for (i = 0; i < fileList->num; i++) {
        ret += fileList->list[i].fileSize;
    }
    return ret;
}

static uint8_t *PreparePackedDFileUserData(uint16_t pathType, const char *userData, uint16_t *packedLen)
{
    UserDataUnit *userDataUnit = NULL;
    uint32_t userDataLen = 0;
    uint16_t packeUserDataLen;

    if (userData != NULL) {
        userDataLen = (uint32_t)strlen(userData);
    }

    packeUserDataLen = (uint16_t)(sizeof(pathType) + userDataLen);

    userDataUnit = (UserDataUnit *)calloc(packeUserDataLen, 1);
    if (userDataUnit == NULL) {
        DFILE_LOGE(TAG, "userDataUnit calloc error");
        return NULL;
    }
    userDataUnit->pathType = pathType;
    if (userDataLen > 0 && memcpy_s(userDataUnit->userData, userDataLen, userData, userDataLen) != EOK) {
        DFILE_LOGE(TAG, "userData memcpy error");
        free(userDataUnit);
        return NULL;
    }
    *packedLen = packeUserDataLen;
    return (uint8_t *)userDataUnit;
}

int32_t FileListAddExtraInfo(FileList *fileList, uint16_t pathType, uint8_t noticeFileNameType, char *userData)
{
    if (noticeFileNameType != NOTICE_FILE_NAME_TYPE && noticeFileNameType != NOTICE_FULL_FILE_NAME_TYPE) {
        DFILE_LOGE(TAG, "invalid noticeFileNameType");
        return NSTACKX_EFAILED;
    }
    fileList->noticeFileNameType = noticeFileNameType;

    if (pathType == 0 && userData == NULL) {
        return NSTACKX_EOK;
    }
    /*
     * the first bit of userDataFlag means whether fileId 0 is vailid, and both pathType and userdata are
     * transferred as part of the fileName of fileId 0.
     */
    fileList->userDataFlag = NSTACKX_DFILE_HEADER_FRAME_USER_DATA_FLAG;

    fileList->userData = userData;
    fileList->pathType = pathType;

    if (pathType > 0) {
        fileList->packedUserData = PreparePackedDFileUserData(pathType, userData, &fileList->packedUserDataLen);
        if (fileList->packedUserData == NULL) {
            DFILE_LOGE(TAG, "PreparePackedDFileUserData fail");
            return NSTACKX_EFAILED;
        }
    }
    return NSTACKX_EOK;
}

int32_t FileListRenameFile(FileList *fileList, uint16_t fileId, const char *newFileName)
{
    if (fileList == NULL || fileId == 0 || fileId > fileList->num || newFileName == NULL ||
        strlen(newFileName) == 0 || strlen(newFileName) >= NSTACKX_MAX_REMOTE_PATH_LEN) {
        return NSTACKX_EINVAL;
    }
    if (strcpy_s(fileList->list[fileId - 1].fileName, NSTACKX_MAX_REMOTE_PATH_LEN, newFileName) != EOK) {
        DFILE_LOGE(TAG, "strcpy_s error");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static void FreeFileListInfo(FileListInfo *fileListInfo, uint32_t end)
{
    while (end != 0) {
        free(fileListInfo->files[end - 1]);
        end--;
    }
    free(fileListInfo->files);
    fileListInfo->files = NULL;
}

static int32_t CopyFilesListInfo(FileListInfo *fileListInfo, FileListPara *fileListPara)
{
    uint32_t i;
    uint32_t end = 0;
    char tmpFileName[PATH_MAX];

    for (i = 0; i < fileListPara->fileNum; i++) {
        /* When second parameter is NULL, realpath() uses malloc() to allocate a buffer of up to PATH_MAX bytes. */
        if (realpath(fileListPara->files[i], tmpFileName) == NULL) {
            DFILE_LOGE(TAG, "CreateFileListInfo realpath %s failed errno %d", fileListPara->files[i], errno);
            end = i;
            goto L_ERR_FILE;
        }
        fileListInfo->files[i] = calloc(1, strlen(fileListPara->files[i]) + 1);
        if (fileListInfo->files[i] == NULL) {
            DFILE_LOGE(TAG, "CreateFileListInfo calloc failed");
            end = i;
            goto L_ERR_FILE;
        }
        if (memcpy_s(fileListInfo->files[i], strlen(fileListPara->files[i]) + 1, fileListPara->files[i],
            strlen(fileListPara->files[i])) != NSTACKX_EOK) {
            DFILE_LOGE(TAG, "memcpy_s failed");
            end = i + 1;
            goto L_ERR_FILE;
        }
        uint32_t len = GetFileNameLen(fileListInfo->files[i]);
        if (len > NSTACKX_MAX_FILE_NAME_LEN || len == 0 || !IsAccessiblePath(fileListInfo->files[i], R_OK, S_IFREG)) {
            DFILE_LOGE(TAG, "file name %s is too long or the file is not a readable file", fileListPara->files[i]);
            end = i + 1;
            goto L_ERR_FILE;
        }

        if (fileListPara->startOffset) {
            fileListInfo->startOffset[i] = fileListPara->startOffset[i];
        }
        if (fileListPara->fileSize) {
            fileListInfo->fileSize[i] = fileListPara->fileSize[i];
        }
    }
    return NSTACKX_EOK;

L_ERR_FILE:
    FreeFileListInfo(fileListInfo, end);
    return NSTACKX_EFAILED;
}

static int32_t FileListInfoAddRemotePath(FileListInfo *fileListInfo, const char *remotePath[], uint32_t fileNum)
{
    uint32_t i;
    uint32_t end = 0;
    if (fileListInfo == NULL || remotePath == NULL || fileNum == 0) {
        DFILE_LOGE(TAG, "invalid input");
        return NSTACKX_EINVAL;
    }
    fileListInfo->remotePath = calloc(fileNum, sizeof(char *));
    if (fileListInfo->remotePath == NULL) {
        return NSTACKX_EFAILED;
    }

    for (i = 0; i < fileNum; i++) {
        if (fileListInfo->tarFlag != NSTACKX_TRUE) {
            fileListInfo->remotePath[i] = strdup(remotePath[i]);
        } else {
            fileListInfo->remotePath[i] = strdup(remotePath[0]);
        }
        if (fileListInfo->remotePath[i] == NULL) {
            DFILE_LOGE(TAG, "failed for copy %uth remotePath, errno(%d)", i, errno);
            end = i;
            goto L_ERR_FILE;
        }
        if (strlen(fileListInfo->remotePath[i]) + 1 > NSTACKX_MAX_REMOTE_PATH_LEN) {
            DFILE_LOGE(TAG, "remotePath is too long");
            end = i + 1;
            goto L_ERR_FILE;
        }
    }

    return NSTACKX_EOK;

L_ERR_FILE:
    while (end > 0) {
        free(fileListInfo->remotePath[end - 1]);
        end--;
    }
    free(fileListInfo->remotePath);
    fileListInfo->remotePath = NULL;
    return NSTACKX_EFAILED;
}

FileListInfo *CreateFileListInfo(FileListPara *fileListPara)
{
    if (fileListPara->fileNum == 0) {
        return NULL;
    }
    FileListInfo *fileListInfo = calloc(1, sizeof(FileListInfo));
    if (fileListInfo == NULL) {
        return NULL;
    }
    fileListInfo->fileNum = fileListPara->fileNum;
    fileListInfo->files = calloc(fileListPara->fileNum, sizeof(char *));
    if (fileListInfo->files == NULL) {
        goto L_ERR_LIST;
    }
    fileListInfo->tarFlag = fileListPara->tarFlag;
    fileListInfo->noSyncFlag = NSTACKX_FALSE;

    if (CopyFilesListInfo(fileListInfo, fileListPara) != NSTACKX_EOK) {
        goto L_ERR_LIST;
    }

    if (fileListPara->userData != NULL) {
        fileListInfo->userData = strdup(fileListPara->userData);
        if (fileListInfo->userData == NULL) {
            goto L_ERR_FILE;
        }
    }

    if (fileListPara->remotePath != NULL &&
        FileListInfoAddRemotePath(fileListInfo, fileListPara->remotePath, fileListPara->fileNum) != NSTACKX_EOK) {
        if (fileListPara->userData != NULL) {
            free(fileListInfo->userData);
            fileListInfo->userData = NULL;
        }
        DFILE_LOGE(TAG, "CreateFileListInfo FileListInfoAddRemotePath failed");
        goto L_ERR_FILE;
    }

    return fileListInfo;

L_ERR_FILE:
    FreeFileListInfo(fileListInfo, fileListPara->fileNum);
L_ERR_LIST:
    free(fileListInfo);
    return NULL;
}

void DestroyFileListInfo(FileListInfo *fileListInfo)
{
    uint32_t i;

    if (fileListInfo == NULL) {
        return;
    }

    for (i = 0; i < fileListInfo->fileNum; i++) {
        free(fileListInfo->files[i]);
    }
    free(fileListInfo->files);
    fileListInfo->files = NULL;

    if (fileListInfo->remotePath != NULL) {
        for (i = 0; i < fileListInfo->fileNum; i++) {
            free(fileListInfo->remotePath[i]);
        }
        free(fileListInfo->remotePath);
        fileListInfo->remotePath = NULL;
    }

    if (fileListInfo->userData != NULL) {
        free(fileListInfo->userData);
        fileListInfo->userData = NULL;
    }
    if (fileListInfo->tarFile != NULL) {
        free(fileListInfo->tarFile);
        fileListInfo->tarFile = NULL;
    }
    free(fileListInfo);
}
