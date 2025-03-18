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

#include "nstackx_dfile.h"
#include "nstackx_util.h"
#include "nstackx_event.h"
#include "nstackx_dfile_log.h"
#include "nstackx_epoll.h"
#include "nstackx_dfile_session.h"
#include "nstackx_dfile_config.h"
#include "nstackx_dfile_mp.h"
#include "nstackx_congestion.h"
#include "nstackx_dfile_dfx.h"
#ifdef MBEDTLS_INCLUDED
#include "nstackx_mbedtls.h"
#else
#include "nstackx_openssl.h"
#endif
#include "nstackx_dfile_private.h"
#include "securec.h"
#include "nstackx_socket.h"
#ifdef DFILE_ENABLE_HIDUMP
#include "nstackx_getopt.h"
#endif

#define TAG "nStackXDFile"
#define Coverity_Tainted_Set(pkt)

#define SOCKET_SEND_BUFFER                 (0x38000 * 15)
#define SOCKET_RECV_BUFFER                 (0x38000 * 192)

/* this lock will been destroy only when process exit. */
static pthread_mutex_t g_dFileSessionIdMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_dFileSessionChainMutex = PTHREAD_MUTEX_INITIALIZER;
List g_dFileSessionChain = {&(g_dFileSessionChain), &(g_dFileSessionChain)};
static uint16_t g_dFileSessionId = 0;
/* currently enabled capabilities */
static uint32_t g_capabilities = NSTACKX_CAPS_WLAN_CATAGORY;
/* wlan catagory from APP */
static uint32_t g_wlanCatagory = NSTACKX_WLAN_CAT_TCP;

typedef struct {
    DFileSession *session;
    char *path;
} DFileSetStoragePathCtx;

typedef struct {
    DFileSession *session;
    OnDFileRenameFile onRenameFile;
} DFileSetRenameHookCtx;

typedef struct {
    DFileSession *session;
    FileListInfo *fileListInfo;
} DFileSendFileCtx;

static int32_t GetDFileSessionId(uint16_t *sessionId)
{
    if (PthreadMutexLock(&g_dFileSessionIdMutex) != 0) {
        return NSTACKX_EFAILED;
    }

    if (g_dFileSessionId == 0) {
        ListInitHead(&g_dFileSessionChain);
    }
    if (g_dFileSessionId == UINT16_MAX) {
        g_dFileSessionId = 1;
    } else {
        g_dFileSessionId++;
    }
    *sessionId = g_dFileSessionId;

    if (PthreadMutexUnlock(&g_dFileSessionIdMutex) != 0) {
        *sessionId = 0;
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

#ifdef DFILE_ENABLE_HIDUMP
DFileSessionNode *GetDFileSessionNodeById(uint16_t sessionId)
#else
static DFileSessionNode *GetDFileSessionNodeById(uint16_t sessionId)
#endif
{
    List *pos = NULL;
    DFileSessionNode *node = NULL;
    uint8_t isFound = NSTACKX_FALSE;
    if (PthreadMutexLock(&g_dFileSessionChainMutex) != 0) {
        DFILE_LOGE(TAG, "lock g_dFileSessionChainMutex failed");
        return NULL;
    }
    LIST_FOR_EACH(pos, &g_dFileSessionChain) {
        node = (DFileSessionNode *)pos;
        if (node->sessionId == sessionId) {
            isFound = NSTACKX_TRUE;
            break;
        }
    }
    if (PthreadMutexUnlock(&g_dFileSessionChainMutex) != 0) {
        DFILE_LOGE(TAG, "unlock g_dFileSessionChainMutex failed");
        return NULL;
    }
    if (isFound) {
        return node;
    }
    return NULL;
}

static int32_t AddDFileSessionNode(DFileSession *session)
{
    DFileSessionNode *node = calloc(1, sizeof(DFileSessionNode));
    if (node == NULL) {
        return NSTACKX_EFAILED;
    }

    node->session = session;
    node->sessionId = session->sessionId;
    if (PthreadMutexLock(&g_dFileSessionChainMutex) != 0) {
        DFILE_LOGE(TAG, "lock g_dFileSessionChainMutex failed");
        free(node);
        return NSTACKX_EFAILED;
    }
    ListInsertTail(&g_dFileSessionChain, &node->list);
    if (PthreadMutexUnlock(&g_dFileSessionChainMutex) != 0) {
        DFILE_LOGE(TAG, "unlock g_dFileSessionChainMutex failed");
        ListRemoveNode(&node->list);
        free(node);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static DFileSessionNode *PopDFileSessionNodeById(uint16_t sessionId)
{
    DFileSessionNode *node = NULL;
    List *pos = NULL;
    List *tmp = NULL;
    uint8_t isFound = NSTACKX_FALSE;
    if (PthreadMutexLock(&g_dFileSessionChainMutex) != 0) {
        DFILE_LOGE(TAG, "lock g_dFileSessionChainMutex failed");
        return NULL;
    }
    LIST_FOR_EACH_SAFE(pos, tmp, &g_dFileSessionChain) {
        node = (DFileSessionNode *)pos;
        if (node->sessionId == sessionId) {
            ListRemoveNode(&node->list);
            isFound = NSTACKX_TRUE;
            break;
        }
    }
    if (PthreadMutexUnlock(&g_dFileSessionChainMutex) != 0) {
        DFILE_LOGE(TAG, "unlock g_dFileSessionChainMutex failed");
        if (node != NULL) {
            ListInsertTail(&g_dFileSessionChain, &node->list);
        }
        return NULL;
    }

    if (isFound) {
        return node;
    }
    return NULL;
}

static int32_t CheckSessionIdValid(int32_t sessionId)
{
    if (sessionId < 0 || sessionId > UINT16_MAX) {
        return NSTACKX_EINVAL;
    }
    return NSTACKX_EOK;
}

static int32_t CheckDFileSessionNodeValid(const DFileSessionNode *node)
{
    if (node == NULL || node->session == NULL) {
        return NSTACKX_EINVAL;
    }
    return NSTACKX_EOK;
}

static int32_t CheckFileNum(uint32_t fileNum)
{
    if (fileNum == 0 || fileNum > NSTACKX_DFILE_MAX_FILE_NUM) {
        return NSTACKX_EINVAL;
    }
    return NSTACKX_EOK;
}

static void DFileSetStoragePathInner(void *arg)
{
    DFileSetStoragePathCtx *ctx = arg;
    if (ctx->session == NULL) {
        free(ctx->path);
        free(ctx);
        return;
    }

    if (FileManagerSetWritePath(ctx->session->fileManager, ctx->path) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "filemanager set write path failed");
    }
    free(ctx->path);
    free(ctx);
}

static int32_t CheckSetStoragePathPara(int32_t sessionId, const char *path)
{
    size_t len;
    if (CheckSessionIdValid(sessionId) != NSTACKX_EOK || path == NULL) {
        DFILE_LOGE(TAG, "invalid arg input");
        return NSTACKX_EINVAL;
    }

    len = strlen(path);
    if (len == 0 || len > NSTACKX_MAX_PATH_LEN) {
        DFILE_LOGE(TAG, "Invalid path name length");
        return NSTACKX_EINVAL;
    }
    return NSTACKX_EOK;
}

int32_t NSTACKX_DFileSetStoragePath(int32_t sessionId, const char *path)
{
    /* EaglEye test */
    Coverity_Tainted_Set((void *)&sessionId);
    Coverity_Tainted_Set((void *)path);

    DFileSetStoragePathCtx *ctx = NULL;

    if (CheckSetStoragePathPara(sessionId, path) != NSTACKX_EOK) {
        return NSTACKX_EINVAL;
    }

    DFileSessionNode *node = GetDFileSessionNodeById((uint16_t)sessionId);
    if (CheckDFileSessionNodeValid(node) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "no session found for id %d", sessionId);
        return NSTACKX_EINVAL;
    }

    ctx = malloc(sizeof(DFileSetStoragePathCtx));
    if (ctx == NULL) {
        return NSTACKX_ENOMEM;
    }

    /* When second parameter is NULL, realpath() uses malloc() to allocate a buffer of up to PATH_MAX bytes. */
    ctx->path = realpath(path, NULL);
    if (ctx->path == NULL) {
        DFILE_LOGE(TAG, "can't get canonicalized absolute pathname");
        free(ctx);
        return NSTACKX_EFAILED;
    }

    if (!IsAccessiblePath(ctx->path, W_OK, S_IFDIR)) {
        DFILE_LOGE(TAG, "the input path isn't a valid writable folder");
        free(ctx->path);
        free(ctx);
        return NSTACKX_EFAILED;
    }

    ctx->session = node->session;

    if (PostEvent(&node->session->eventNodeChain, node->session->epollfd, DFileSetStoragePathInner, ctx) !=
        NSTACKX_EOK) {
        free(ctx->path);
        free(ctx);
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

static uint8_t HasRepeatedNumber(const uint16_t *data, uint16_t len)
{
    uint16_t i, j;
    for (i = 0; i < len; i++) {
        for (j = i + 1; j < len; j++) {
            if (data[i] == data[j]) {
                return NSTACKX_TRUE;
            }
        }
    }
    return NSTACKX_FALSE;
}

typedef struct {
    DFileSession *session;
    char *pathList[NSTACKX_MAX_STORAGE_PATH_NUM];
    uint16_t pathType[NSTACKX_MAX_STORAGE_PATH_NUM];
    uint16_t pathNum;
} DFileSetStoragePathListCtx;

static void ClearStoragePathListCtx(DFileSetStoragePathListCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    for (uint16_t i = 0; i < ctx->pathNum; i++) {
        free(ctx->pathList[i]);
        ctx->pathList[i] = NULL;
    }
    free(ctx);
}

static void DFileSetStoragePathListInner(void *arg)
{
    DFileSetStoragePathListCtx *ctx = arg;

    if (ctx == NULL) {
        return;
    }

    if (ctx->session == NULL) {
        ClearStoragePathListCtx(ctx);
        return;
    }

    if (FileManagerSetWritePathList(ctx->session->fileManager, ctx->pathList, ctx->pathType, ctx->pathNum) !=
        NSTACKX_EOK) {
        ClearStoragePathListCtx(ctx);
        return;
    }

    /* if set filemanager write path list successfully, the pathList menmber will be freed in filemanager */
    free(ctx);
}

DFileSetStoragePathListCtx *CreateStoragePathListCtx(const DFileSession *session, const char *path[],
                                                     const uint16_t *pathType, uint16_t pathNum)
{
    DFileSetStoragePathListCtx *ctx = NULL;
    uint16_t i, pos;

    if (pathNum > NSTACKX_MAX_STORAGE_PATH_NUM) {
        DFILE_LOGE(TAG, "invalid pathNum");
        return NULL;
    }

    ctx = malloc(sizeof(DFileSetStoragePathListCtx));
    if (ctx == NULL) {
        return NULL;
    }

    for (i = 0; i < pathNum; i++) {
        /* When second parameter is NULL, realpath() uses malloc() to allocate a buffer of up to PATH_MAX bytes. */
        ctx->pathList[i] = realpath(path[i], NULL);
        if (ctx->pathList[i] == NULL) {
            DFILE_LOGE(TAG, "can't get canonicalized absolute pathname");
            pos = i;
            goto L_ERR;
        }
        if (!IsAccessiblePath(ctx->pathList[i], W_OK, S_IFDIR)) {
            DFILE_LOGE(TAG, "the input path isn't a valid writable folder");
            pos = i + 1;
            goto L_ERR;
        }
        ctx->pathType[i] = pathType[i];
    }
    ctx->pathNum = pathNum;
    ctx->session = (DFileSession *)session;
    return ctx;

L_ERR:
    while (pos > 0) {
        free(ctx->pathList[pos - 1]);
        ctx->pathList[pos - 1] = NULL;
        pos--;
    }
    free(ctx);
    return NULL;
}

static int32_t CheckSetStoragePathListPara(int32_t sessionId, const char *path[], const uint16_t *pathType,
                                           uint16_t pathNum)
{
    if (CheckSessionIdValid(sessionId) != NSTACKX_EOK || path == NULL || pathType == NULL || pathNum == 0 ||
        pathNum > NSTACKX_MAX_STORAGE_PATH_NUM) {
        DFILE_LOGE(TAG, "invalid arg input");
        return NSTACKX_EINVAL;
    }

    if (HasRepeatedNumber(pathType, pathNum)) {
        DFILE_LOGE(TAG, "has repeated type");
        return NSTACKX_EINVAL;
    }
    return NSTACKX_EOK;
}

int32_t NSTACKX_DFileSetStoragePathList(int32_t sessionId, const char *path[], const uint16_t *pathType,
                                        uint16_t pathNum)
{
    /* EaglEye test */
    Coverity_Tainted_Set((void *)&sessionId);
    Coverity_Tainted_Set((void *)path);
    Coverity_Tainted_Set((void *)pathType);
    Coverity_Tainted_Set((void *)&pathNum);

    DFileSetStoragePathListCtx *ctx = NULL;

    if (CheckSetStoragePathListPara(sessionId, path, pathType, pathNum) != NSTACKX_EOK) {
        return NSTACKX_EINVAL;
    }

    DFileSessionNode *node = GetDFileSessionNodeById((uint16_t)sessionId);
    if (CheckDFileSessionNodeValid(node) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "no session found for id %d", sessionId);
        return NSTACKX_EINVAL;
    }

    ctx = CreateStoragePathListCtx(node->session, path, pathType, pathNum);
    if (ctx == NULL) {
        return NSTACKX_ENOMEM;
    }

    if (PostEvent(&node->session->eventNodeChain, node->session->epollfd, DFileSetStoragePathListInner, ctx) !=
        NSTACKX_EOK) {
        ClearStoragePathListCtx(ctx);
        ctx = NULL;
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static inline void AddFileList(DFileSession *session, FileListInfo *fileListInfo)
{
#ifdef NSTACKX_SMALL_FILE_SUPPORT
    if (fileListInfo->smallFlag == NSTACKX_TRUE) {
        ListInsertTail(&session->smallFileLists, &fileListInfo->list);
        session->smallListPendingCnt++;
    } else {
        ListInsertTail(&session->pendingFileLists, &fileListInfo->list);
        session->fileListPendingCnt++;
    }
#else
    ListInsertTail(&session->pendingFileLists, &fileListInfo->list);
    session->fileListPendingCnt++;
#endif
}

static void DFileSendFileFail(void *arg)
{
    DFileSendFileCtx *ctx = arg;
    DFileSession *session = ctx->session;
    DFileMsg data;

    (void)memset_s(&data, sizeof(data), 0, sizeof(data));
    data.errorCode = NSTACKX_EINVAL;
    data.fileList.files = (const char **)ctx->fileListInfo->files;
    data.fileList.fileNum = ctx->fileListInfo->fileNum;
    data.fileList.userData = ctx->fileListInfo->userData;
    NotifyMsgRecver(session, DFILE_ON_FILE_SEND_FAIL, &data);
    DestroyFileListInfo(ctx->fileListInfo);
    free(ctx);
}

static void DFileSendFileInner(void *arg)
{
    DFileSendFileCtx *ctx = arg;
    DFileSession *session = ctx->session;
    DFileMsg data;

    DFileSendFileBeginEvent();

    (void)memset_s(&data, sizeof(data), 0, sizeof(data));
    if (session == NULL) {
        data.errorCode = NSTACKX_EINVAL;
        DFILE_LOGE(TAG, "session is NULL");
        goto L_END;
    }
#ifdef NSTACKX_SMALL_FILE_SUPPORT
    uint32_t totalCnt = session->fileListProcessingCnt + session->fileListPendingCnt + session->smallListProcessingCnt +
        session->smallListPendingCnt;
#else
    uint32_t totalCnt = session->fileListProcessingCnt + session->fileListPendingCnt;
#endif
    DFILE_LOGI(TAG, "recv filelist fileNum %u tarFlag %hhu path %s, total %u", ctx->fileListInfo->fileNum,
        ctx->fileListInfo->tarFlag, ctx->fileListInfo->files[0], totalCnt + 1);
    CalculateSessionTransferRatePrepare(session);
    if (session->fileListProcessingCnt + session->smallListProcessingCnt >= NSTACKX_FILE_MANAGER_THREAD_NUM) {
        AddFileList(session, ctx->fileListInfo);
    } else {
        int32_t ret = DFileStartTrans(session, ctx->fileListInfo);
        if (ret != NSTACKX_EOK) {
            data.errorCode = ret;
            DFILE_LOGE(TAG, "DFileStartTrans fail, error: %d", ret);
            goto L_END;
        }
    }

    free(ctx);
    return;

L_END:
    data.fileList.files = (const char **)ctx->fileListInfo->files;
    data.fileList.fileNum = ctx->fileListInfo->fileNum;
    data.fileList.userData = ctx->fileListInfo->userData;
    NotifyMsgRecver(session, DFILE_ON_FILE_SEND_FAIL, &data);
    DestroyFileListInfo(ctx->fileListInfo);
    free(ctx);
}

static uint8_t IsValidStringArray(const char *str[], uint32_t fileNum, size_t maxLen)
{
    if (str == NULL || fileNum == 0) {
        return NSTACKX_FALSE;
    }
    for (uint32_t i = 0; i < fileNum; i++) {
        if (str[i] == NULL) {
            return NSTACKX_FALSE;
        }
        size_t len = strlen(str[i]);
        if (len == 0 || len > maxLen) {
            return NSTACKX_FALSE;
        }
    }
    return NSTACKX_TRUE;
}

static int32_t CheckSendFilesPara(int32_t sessionId, const char *files[], uint32_t fileNum, const char *userData)
{
    size_t userDataLen;
    if (CheckSessionIdValid(sessionId) != NSTACKX_EOK ||
        !IsValidStringArray(files, fileNum, NSTACKX_MAX_FILE_NAME_LEN)) {
        return NSTACKX_EINVAL;
    }

    if (CheckFileNum(fileNum) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "fileNum to send is 0 or too large");
        return NSTACKX_EINVAL;
    }

    if (userData == NULL) {
        userDataLen = 0;
        DFILE_LOGW(TAG, "send file with no user data.");
    } else {
        userDataLen = strlen(userData);
    }

    if (userDataLen > NSTACKX_MAX_USER_DATA_SIZE) {
        DFILE_LOGE(TAG, "send file with too long user data len");
        return NSTACKX_EINVAL;
    }
    return NSTACKX_EOK;
}

void SetVtransInfo(DFileSendFileCtx *ctx, DFileRebuildFileList *rFilelist, uint16_t index)
{
    if (rFilelist->realTransId > 0) {
        ctx->fileListInfo->vtransFlag = NSTACKX_TRUE;
        ctx->fileListInfo->vtransTotalNum = rFilelist->transNum;
        ctx->fileListInfo->vtransRealTransId = rFilelist->realTransId;
        ctx->fileListInfo->vtransRealFileId = rFilelist->realFileId[index];
        ctx->fileListInfo->vtransTotalFileNum = rFilelist->totalFileNum;
        ctx->fileListInfo->vtransTotalFileSize = rFilelist->totalFileSize;
    }
}

int32_t SendFilesInner(int32_t sessionId, const char *files[], const char *remotePath[],
    uint32_t fileNum, const char *userData)
{
    DFileRebuildFileList rFilelist;

    DFileSessionNode *node = GetDFileSessionNodeById((uint16_t)sessionId);
    if (CheckDFileSessionNodeValid(node) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "no session found for id %d", sessionId);
        return NSTACKX_EINVAL;
    }
    if (RebuildFilelist(files, remotePath, fileNum, node->session, &rFilelist) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    for (uint16_t i = 0; i < rFilelist.transNum; i++) {
        DFileSendFileCtx *ctx = malloc(sizeof(DFileSendFileCtx));
        if (ctx == NULL) {
            DFILE_LOGE(TAG, "malloc ctx error: NULL");
            return NSTACKX_ENOMEM;
        }
        ctx->session = node->session;

        FileListPara para = NEW_FILE_LIST_PARA(&(rFilelist.files[i]), (remotePath ? &(rFilelist.remotePath[i]) : NULL),
            (rFilelist.realTransId ? 1 : fileNum), userData,
            NSTACKX_FALSE, &(rFilelist.startOffset[i]), &(rFilelist.fileSize[i]));
        ctx->fileListInfo = CreateFileListInfo(&para);
        if (ctx->fileListInfo == NULL) {
            DFILE_LOGE(TAG, "CreateFileListInfo error: NULL");
            free(ctx);
            return NSTACKX_ENOMEM;
        }
        SetVtransInfo(ctx, &rFilelist, i);

        ctx->fileListInfo->noticeFileNameType = remotePath ? NOTICE_FULL_FILE_NAME_TYPE : NOTICE_FILE_NAME_TYPE;
        ctx->fileListInfo->pathType = NSTACKX_RESERVED_PATH_TYPE;
        ctx->fileListInfo->tarFlag = NSTACKX_FALSE;
        ctx->fileListInfo->smallFlag = NSTACKX_FALSE;
        int32_t ret = PostEvent(&node->session->eventNodeChain, node->session->epollfd, DFileSendFileInner, ctx);
        if (ret != NSTACKX_EOK) {
            DestroyFileListInfo(ctx->fileListInfo);
            free(ctx);
            return ret;
        }
    }

    node->session->allTaskCount++;

    return NSTACKX_EOK;
}

int32_t NSTACKX_DFileSendFiles(int32_t sessionId, const char *files[], uint32_t fileNum, const char *userData)
{
    /* EaglEye test */
    Coverity_Tainted_Set((void *)&sessionId);
    Coverity_Tainted_Set((void *)files);
    Coverity_Tainted_Set((void *)&fileNum);
    Coverity_Tainted_Set((void *)userData);

    if (CheckSendFilesPara(sessionId, files, fileNum, userData) != NSTACKX_EOK) {
        return NSTACKX_EINVAL;
    }

    return SendFilesInner(sessionId, files, NULL, fileNum, userData);
}

static int32_t CheckSendFilesWithRemotePathPara(int32_t sessionId, const char *files[], const char *remotePath[],
                                                uint32_t fileNum, const char *userData)
{
    if (CheckSessionIdValid(sessionId) != NSTACKX_EOK ||
        !IsValidStringArray(files, fileNum, NSTACKX_MAX_FILE_NAME_LEN) ||
        !IsValidStringArray(remotePath, fileNum, NSTACKX_MAX_REMOTE_PATH_LEN)) {
        DFILE_LOGE(TAG, "invalid arg input");
        return NSTACKX_EINVAL;
    }
    if (CheckFileNum(fileNum) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "fileNum to send is 0 or too large");
        return NSTACKX_EINVAL;
    }

    if (userData != NULL && strlen(userData) > NSTACKX_MAX_USER_DATA_SIZE) {
        DFILE_LOGE(TAG, "send file with too long user data len");
        return NSTACKX_EINVAL;
    }
    return NSTACKX_EOK;
}

int32_t NSTACKX_DFileSendFilesWithRemotePath(int32_t sessionId, const char *files[], const char *remotePath[],
                                             uint32_t fileNum, const char *userData)
{
    /* EaglEye test */
    Coverity_Tainted_Set((void *)&sessionId);
    Coverity_Tainted_Set((void *)files);
    Coverity_Tainted_Set((void *)remotePath);
    Coverity_Tainted_Set((void *)&fileNum);
    Coverity_Tainted_Set((void *)userData);

    if (remotePath == NULL) {
        return NSTACKX_DFileSendFiles(sessionId, files, fileNum, userData);
    }

    if (CheckSendFilesWithRemotePathPara(sessionId, files, remotePath, fileNum, userData) != NSTACKX_EOK) {
        return NSTACKX_EINVAL;
    }

    return SendFilesInner(sessionId, files, remotePath, fileNum, userData);
}

static int32_t CheckSendFilesWithRemotePathAndType(int32_t sessionId, NSTACKX_FilesInfo *filesInfo)
{
    if (CheckSessionIdValid(sessionId) != NSTACKX_EOK) {
        return NSTACKX_EINVAL;
    }
    if (filesInfo == NULL || CheckFileNum(filesInfo->fileNum) != NSTACKX_EOK) {
        return NSTACKX_EINVAL;
    }
    if (filesInfo->pathType == NSTACKX_RESERVED_PATH_TYPE) {
        return NSTACKX_EINVAL;
    }
    if (!IsValidStringArray(filesInfo->files, filesInfo->fileNum, NSTACKX_MAX_FILE_NAME_LEN)) {
        return NSTACKX_EINVAL;
    }
    if (filesInfo->tarFlag == NSTACKX_TRUE) {
        /* when tarFlag is set, only remotePath[0] will be accessed */
        if (!IsValidStringArray(filesInfo->remotePath, 1, NSTACKX_MAX_REMOTE_PATH_LEN)) {
            return NSTACKX_EINVAL;
        }
    } else {
        if (!IsValidStringArray(filesInfo->remotePath, filesInfo->fileNum, NSTACKX_MAX_REMOTE_PATH_LEN)) {
            return NSTACKX_EINVAL;
        }
    }
    if (filesInfo->userData != NULL && strlen(filesInfo->userData) > NSTACKX_MAX_USER_DATA_SIZE) {
        DFILE_LOGE(TAG, "send file with too long user data len");
        return NSTACKX_EINVAL;
    }
    return NSTACKX_EOK;
}

static void PostSendFailAsync(int32_t sessionId, const NSTACKX_FilesInfo *filesInfo)
{
    const char *firstFileName = NULL;
    if (CheckSessionIdValid(sessionId) != NSTACKX_EOK || filesInfo == NULL) {
        return;
    }
    if (filesInfo->tarFlag == NSTACKX_TRUE) {
        firstFileName = filesInfo->remotePath[0];
    } else {
        firstFileName = filesInfo->files[0];
    }
    if (firstFileName == NULL) {
        return;
    }
    DFileSessionNode *node = GetDFileSessionNodeById((uint16_t)sessionId);
    if (CheckDFileSessionNodeValid(node) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "no session found for id %d", sessionId);
        return;
    }
    DFileSendFileCtx *ctx = calloc(1, sizeof(DFileSendFileCtx));
    if (ctx == NULL) {
        return;
    }
    ctx->session = node->session;
    ctx->fileListInfo = calloc(1, sizeof(FileListInfo));
    if (ctx->fileListInfo == NULL) {
        goto L_ERR;
    }
    ctx->fileListInfo->fileNum = 1;
    ctx->fileListInfo->files = calloc(1, sizeof(char *));
    if (ctx->fileListInfo->files == NULL) {
        goto L_ERR;
    }
    ctx->fileListInfo->files[0] = calloc(1, strlen(firstFileName) + 1);
    if (ctx->fileListInfo->files[0] == NULL) {
        goto L_ERR;
    }
    if (memcpy_s(ctx->fileListInfo->files[0], strlen(firstFileName) + 1,
        firstFileName, strlen(firstFileName)) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "memcpy_s failed");
        goto L_ERR;
    }
    if (PostEvent(&node->session->eventNodeChain, node->session->epollfd, DFileSendFileFail, ctx) == NSTACKX_EOK) {
        return;
    }
L_ERR:
    DestroyFileListInfo(ctx->fileListInfo);
    free(ctx);
}

static int32_t PackPrepareTar(const char *remotePath, char *tarName, uint32_t maxNameLen)
{
    (void)remotePath;
    (void)tarName;
    (void)maxNameLen;
    return NSTACKX_EOK;
}

int32_t NSTACKX_DFileSendFilesWithRemotePathAndType(int32_t sessionId, NSTACKX_FilesInfo *filesInfo)
{
    /* EaglEye test */
    Coverity_Tainted_Set((void *)filesInfo);

    char tarName[PATH_MAX + 1] = {0};
    if (CheckSendFilesWithRemotePathAndType(sessionId, filesInfo) != NSTACKX_EOK) {
        PostSendFailAsync(sessionId, filesInfo);
        return NSTACKX_EINVAL;
    }

    if (filesInfo->tarFlag == NSTACKX_TRUE) {
        DFILE_LOGE(TAG, "warning: tarflag is not supported now");
        (void)PackPrepareTar(filesInfo->remotePath[0], tarName, PATH_MAX);
        return NSTACKX_NOTSUPPORT;
    }

    DFileSessionNode *node = GetDFileSessionNodeById((uint16_t)sessionId);
    if (CheckDFileSessionNodeValid(node) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "no session found for id %d", sessionId);
        return NSTACKX_EINVAL;
    }

    DFileSendFileCtx *ctx = malloc(sizeof(DFileSendFileCtx));
    if (ctx == NULL) {
        return NSTACKX_ENOMEM;
    }
    ctx->session = node->session;
    FileListPara fileListPara = NEW_FILE_LIST_PARA(filesInfo->files, filesInfo->remotePath, filesInfo->fileNum,
        filesInfo->userData, filesInfo->tarFlag, NULL, NULL);
    ctx->fileListInfo = CreateFileListInfo(&fileListPara);
    if (ctx->fileListInfo == NULL) {
        free(ctx);
        ctx = NULL;
        PostSendFailAsync(sessionId, filesInfo);
        return NSTACKX_ENOMEM;
    }
#ifdef NSTACKX_SMALL_FILE_SUPPORT
    ctx->fileListInfo->smallFlag = filesInfo->smallFlag;
#else
    ctx->fileListInfo->smallFlag = NSTACKX_FALSE;
#endif
    ctx->fileListInfo->noSyncFlag = NSTACKX_TRUE;
    ctx->fileListInfo->noticeFileNameType = NOTICE_FULL_FILE_NAME_TYPE;
    ctx->fileListInfo->pathType = filesInfo->pathType;
    ctx->fileListInfo->tarFile = strdup(tarName);

    int32_t ret = PostEvent(&node->session->eventNodeChain, node->session->epollfd, DFileSendFileInner, ctx);
    if (ret != NSTACKX_EOK) {
        DestroyFileListInfo(ctx->fileListInfo);
        free(ctx);
        ctx = NULL;
        return ret;
    }
    return NSTACKX_EOK;
}

static void DFileSessionBaseInit(DFileSession *session, DFileSessionType type, DFileMsgReceiver msgReceiver,
    uint16_t sessionId)
{
    uint32_t i;

    session->sessionId = sessionId;
    session->transFlag = NSTACKX_FALSE;
    session->bindType = INIT_STATUS;
    session->sessionType = type;
    session->msgReceiver = msgReceiver;
    session->peerInfoCnt = 0;
    ListInitHead(&session->eventNodeChain);
    ListInitHead(&session->dFileTransChain);
    ListInitHead(&session->peerInfoChain);
    ListInitHead(&session->outboundQueue);
    ListInitHead(&session->inboundQueue);
    ListInitHead(&session->pendingFileLists);
    ListInitHead(&session->vtransManagerList);
#ifdef NSTACKX_SMALL_FILE_SUPPORT
    ListInitHead(&session->smallFileLists);
#endif

    for (i = 0; i < NSTACKX_FILE_MANAGER_THREAD_NUM; i++) {
        session->transSlot[i].isWorking = NSTACKX_FALSE;
        session->transSlot[i].transId = 0;
        session->transSlot[i].peerInfo = NULL;
    }

    for (i = 0; i < NSTACKX_MAX_CLIENT_SEND_THREAD_NUM; i++) {
        ListInitHead(&session->freeIovList[i]);
    }
}

static int32_t DFileSessionMutexInit(DFileSession *session)
{
    if (session == NULL) {
        return NSTACKX_EFAILED;
    }
    if (PthreadMutexInit(&session->outboundQueueLock, NULL) != 0) {
        goto L_ERR_OUTBOUND_QUEUE_LOCK;
    }
    if (PthreadMutexInit(&session->inboundQueueLock, NULL) != 0) {
        goto L_ERR_INBOUND_QUEUE_LOCK;
    }

    if (PthreadMutexInit(&session->transIdLock, NULL) != 0) {
        goto L_ERR_TRANS_ID_LOCK;
    }

    if (PthreadMutexInit(&session->backPressLock, NULL) != 0) {
        goto L_ERR_BACKPRESS_LOCK;
    }

    if (MutexListInit(&session->transferDoneAckList, MAX_TRANSFERDONE_ACK_NODE_COUNT) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "transferDoneAckList InitList error");
        goto L_ERR_TRANS_DONE_ACK_LOCK;
    }

    if (MutexListInit(&session->tranIdStateList, MAX_TRANSTATELISTSIZE) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "tranIdStateList InitList error");
        goto L_ERR_TRANS_STATE_LOCK;
    }
    return NSTACKX_EOK;
L_ERR_TRANS_STATE_LOCK:
    MutexListDestory(&session->transferDoneAckList);
L_ERR_TRANS_DONE_ACK_LOCK:
    PthreadMutexDestroy(&session->backPressLock);
L_ERR_BACKPRESS_LOCK:
    PthreadMutexDestroy(&session->transIdLock);
L_ERR_TRANS_ID_LOCK:
    PthreadMutexDestroy(&session->inboundQueueLock);
L_ERR_INBOUND_QUEUE_LOCK:
    PthreadMutexDestroy(&session->outboundQueueLock);
L_ERR_OUTBOUND_QUEUE_LOCK:
    return NSTACKX_EFAILED;
}

static inline void PostSessionCreate(DFileSession *session)
{
    session->capability = g_capabilities;
    session->wlanCatagory = g_wlanCatagory;
    session->cipherCapability = NSTACKX_CIPHER_AES_GCM | NSTACKX_CIPHER_CHACHA;
    DFILE_LOGI(TAG, "current capabilities tcp:%d", CapsTcp(session));
}

static DFileSession *DFileSessionCreate(DFileSessionType type, DFileMsgReceiver msgReceiver)
{
    uint16_t sessionId = 0;
    if (GetDFileSessionId(&sessionId) != NSTACKX_EOK) {
        return NULL;
    }

    DFileSession *session = calloc(1, sizeof(DFileSession));
    if (session == NULL) {
        return NULL;
    }

    if (type == DFILE_SESSION_TYPE_CLIENT) {
        DFileClientCreateEvent();
    }
    if (type == DFILE_SESSION_TYPE_SERVER) {
        DFileServerCreateEvent();
    }

    DFileSessionBaseInit(session, type, msgReceiver, sessionId);

    if (InitOutboundQueueWait(session) != NSTACKX_EOK) {
        goto L_ERR_SEM;
    }

    session->epollfd = CreateEpollDesc();
    if (!IsEpollDescValid(session->epollfd)) {
        goto L_ERR_EPOLL;
    }

    session->recvBuffer = calloc(1, NSTACKX_RECV_BUFFER_LEN);
    if (session->recvBuffer == NULL) {
        DFILE_LOGE(TAG, "can not get memory");
        goto L_ERR_RECVBUFFER;
    }

    if (DFileSessionMutexInit(session) != NSTACKX_EOK) {
        goto L_ERR_MUTEX;
    }
    PostSessionCreate(session);
    return session;
L_ERR_MUTEX:
    free(session->recvBuffer);
L_ERR_RECVBUFFER:
    CloseEpollDesc(session->epollfd);
L_ERR_EPOLL:
    DestroyOutboundQueueWait(session);
L_ERR_SEM:
    free(session);
    return NULL;
}

static void DFileClearTransferDoneAckList(DFileSession *session)
{
    List *pos = NULL;
    List *tmp = NULL;
    TransferDoneAckNode *transferDoneAckNode = NULL;
    if (PthreadMutexLock(&session->transferDoneAckList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        return;
    }
    LIST_FOR_EACH_SAFE(pos, tmp, &session->transferDoneAckList.head) {
        transferDoneAckNode = (TransferDoneAckNode *)pos;
        ListRemoveNode(&transferDoneAckNode->list);
        free(transferDoneAckNode);
        session->transferDoneAckList.size--;
    }
    if (PthreadMutexUnlock(&session->transferDoneAckList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
        return;
    }
    return;
}

static void DFileSessionClean(DFileSession *session)
{
    List *tmp = NULL;
    List *pos = NULL;
    PeerInfo *peerInfo = NULL;

    LIST_FOR_EACH_SAFE(pos, tmp, &session->peerInfoChain) {
        peerInfo = (PeerInfo *)pos;
        if (peerInfo->settingTimer != NULL) {
            TimerDelete(peerInfo->settingTimer);
            peerInfo->settingTimer = NULL;
        }
        ListRemoveNode(&peerInfo->list);
        free(peerInfo);
    }
    if (IsEpollDescValid(session->epollfd)) {
        CloseEpollDesc(session->epollfd);
        session->epollfd = INVALID_EPOLL_DESC;
    }
    DestroyOutboundQueueWait(session);
    PthreadMutexDestroy(&session->inboundQueueLock);
    PthreadMutexDestroy(&session->outboundQueueLock);
    PthreadMutexDestroy(&session->transIdLock);
    PthreadMutexDestroy(&session->backPressLock);
    DFileClearTransferDoneAckList(session);
    MutexListDestory(&session->transferDoneAckList);
    MutexListDestory(&session->tranIdStateList);
    free(session->recvBuffer);
    free(session);
    return;
}

static int32_t DFileRecverInit(DFileSession *session, struct sockaddr_in *sockAddr, uint8_t socketIndex)
{
    SocketProtocol protocol;

    if (CapsTcp(session)) {
        protocol = NSTACKX_PROTOCOL_TCP;
    } else {
        protocol = NSTACKX_PROTOCOL_UDP;
    }

    Socket *socket = ServerSocket(protocol, sockAddr);
    if (socket == NULL) {
        return NSTACKX_EFAILED;
    }

    /* Note: If the monitoring method is not select, this restriction should be removed */
    if (CheckFdSetSize(socket->sockfd) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "CheckFdSetSize failed");
        CloseSocket(socket);
        return NSTACKX_EFAILED;
    }

    session->socket[socketIndex] = socket;
    session->protocol = protocol;
    DFILE_LOGI(TAG, "create server socket %d protocol is %d", socket->sockfd, protocol);
    int32_t optVal = 0;
    socklen_t optLen = sizeof(optVal);
    if (getsockopt(socket->sockfd, SOL_SOCKET, SO_RCVBUF, (void *)&optVal, &optLen) == 0) {
        DFILE_LOGI(TAG, "default recv buf is %d bytes", optVal);
    }

    return NSTACKX_EOK;
}

static void DFileRecverDestory(DFileSession *session)
{
    CloseSocket(session->socket[0]);
    CloseSocket(session->socket[1]);
    session->socket[0] = NULL;
    session->socket[1] = NULL;
}

static int32_t StartDFileThreads(DFileSession *session)
{
    if (CreateReceiverPipe(session) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "Create pipe failed");
        goto L_ERR_PIPE;
    }

    if (EventModuleInit(&session->eventNodeChain, session->epollfd) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "Event module init failed!");
        goto L_ERR_EVENT;
    }

    if (StartDFileThreadsInner(session) == NSTACKX_EOK) {
        return NSTACKX_EOK;
    }

    EventNodeChainClean(&session->eventNodeChain);
    CloseEpollDesc(session->epollfd);
    session->epollfd = INVALID_EPOLL_DESC;
L_ERR_EVENT:
    DestroyReceiverPipe(session);
L_ERR_PIPE:
    return NSTACKX_EFAILED;
}

static void StopDFileThreads(DFileSession *session)
{
    /* Notify main loop thread to terminate */
    if (PostEvent(&session->eventNodeChain, session->epollfd, TerminateMainThreadInner, session) != NSTACKX_EOK) {
        DFileSessionSetTerminateFlag(session);

        /* Notify sender thread to terminate */
        PostOutboundQueueWait(session);

        /* Unblock "select" and notify receiver thread to terminate */
        NotifyPipeEvent(session);
    }

    /* Terminate 3 handling threads */
    PthreadJoin(session->tid, NULL);
    session->tid = INVALID_TID;

    PthreadJoin(session->senderTid[0], NULL);
    session->senderTid[0] = INVALID_TID;

    PthreadJoin(session->receiverTid, NULL);
    session->receiverTid = INVALID_TID;
    PthreadJoin(session->controlTid, NULL);
    session->controlTid = INVALID_TID;

    /* Terminate file IO thread */
    StopFileManagerThreads(session->fileManager);
    /* Clear event callback */
    ClearEvent(&session->eventNodeChain, session->epollfd);
    EventNodeChainClean(&session->eventNodeChain);
    CloseEpollDesc(session->epollfd);
    session->epollfd = INVALID_EPOLL_DESC;
    DestroyReceiverPipe(session);
}

int32_t StartSessionRunning(DFileSession *session, uint16_t SendThreadNum)
{
    session->clientSendThreadNum = SendThreadNum;
    if (StartDFileThreads(session) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    if (AddDFileSessionNode(session) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

static int32_t NSTACKX_DFileInit(void)
{
    if (SocketModuleInit() != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    if (CongModuleInit() != NSTACKX_EOK) {
        goto L_ERR_CONG;
    }
#ifdef NSTACKX_WITH_LITEOS
    EpollEventPtrInit();
#endif

    return NSTACKX_EOK;

L_ERR_CONG:
    SocketModuleClean();
    DFILE_LOGE(TAG, "fail to create dfile server ");
    return NSTACKX_EFAILED;
}

int32_t NSTACKX_DFileServer(struct sockaddr_in *localAddr, socklen_t addrLen, const uint8_t *key, uint32_t keyLen,
                            DFileMsgReceiver msgReceiver)
{
    /* EaglEye test */
    Coverity_Tainted_Set((void *)localAddr);
    Coverity_Tainted_Set((void *)&addrLen);
    Coverity_Tainted_Set((void *)key);
    Coverity_Tainted_Set((void *)&keyLen);
    Coverity_Tainted_Set((void *)msgReceiver);

    DFILE_LOGI(TAG, "Begin to create dfile server ");
    DFileSession *session = NULL;
    struct sockaddr_in sockAddr;

    if (localAddr == NULL || localAddr->sin_family != AF_INET || sizeof(struct sockaddr_in) != addrLen) {
        return NSTACKX_EFAILED;
    }
    if (NSTACKX_DFileInit() != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    session = DFileSessionCreate(DFILE_SESSION_TYPE_SERVER, msgReceiver);
    if (session == NULL) {
        goto L_ERR_SESSION;
    }

    (void)memset_s(&sockAddr, sizeof(sockAddr), 0, sizeof(sockAddr));
    sockAddr.sin_port = htons(localAddr->sin_port);
    sockAddr.sin_addr.s_addr = htonl(localAddr->sin_addr.s_addr);
    if (DFileRecverInit(session, &sockAddr, 0) != NSTACKX_EOK) {
        goto L_ERR_RECVER_INIT;
    }

    if (CreateFileManager(session, key, keyLen, NSTACKX_FALSE, CONNECT_TYPE_NONE) != NSTACKX_EOK) {
        goto L_ERR_FILE_MANAGER;
    }

    if (StartSessionRunning(session, 1) != NSTACKX_EOK) {
        goto L_ERR_THREAD;
    }

    return session->sessionId;
L_ERR_THREAD:
    StopFileManagerThreads(session->fileManager);
    FileManagerDestroy(session->fileManager);
L_ERR_FILE_MANAGER:
    DFileRecverDestory(session);
L_ERR_RECVER_INIT:
    DFileSessionClean(session);
L_ERR_SESSION:
    CongModuleClean();
    SocketModuleClean();
    DFILE_LOGE(TAG, "fail to create dfile server ");
    return NSTACKX_EFAILED;
}

static int32_t DFileSenderInitWithTargetDev(DFileSession *session, const struct sockaddr_in *sockAddr,
                                            uint16_t *connType, const char *localInterface, uint8_t socketIndex)
{
    SocketProtocol protocol;

    protocol = CapsTcp(session) ? NSTACKX_PROTOCOL_TCP : NSTACKX_PROTOCOL_UDP;

    Socket *socket = ClientSocketWithTargetDev(protocol, sockAddr, localInterface);
    if (socket == NULL) {
        DFILE_LOGE(TAG, "socket is null");
        return NSTACKX_EFAILED;
    }

    /* Note: If the monitoring method is not select, this restriction should be removed */
    if (CheckFdSetSize(socket->sockfd) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "CheckFdSetSize failed");
        CloseSocket(socket);
        return NSTACKX_EFAILED;
    }

    session->socket[socketIndex] = socket;
    session->protocol = protocol;

    if (CapsTcp(session)) {
        SetTcpKeepAlive(socket->sockfd);
    }

    int32_t ret = GetConnectionType(socket->srcAddr.sin_addr.s_addr, socket->dstAddr.sin_addr.s_addr,
                                    connType);
    if (ret != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "get connect type failed, ret = %d", ret);
        goto L_ERR_PEER_INFO;
    }
    if ((*connType != CONNECT_TYPE_P2P && *connType != CONNECT_TYPE_WLAN)) {
        *connType = CONNECT_TYPE_WLAN;
        DFILE_LOGI(TAG, "connet type isn't wlan or p2p, and will be set to wlan by default");
    }
    PeerInfo *peerInfo = CreatePeerInfo(session, &socket->dstAddr, 0, *connType, socketIndex);
    if (peerInfo == NULL) {
        goto L_ERR_PEER_INFO;
    }
    ListInsertTail(&session->peerInfoChain, &peerInfo->list);
    *connType = peerInfo->connType;
    return NSTACKX_EOK;

L_ERR_PEER_INFO:
    CloseSocket(session->socket[0]);
    CloseSocket(session->socket[1]);
    session->socket[0] = NULL;
    session->socket[1] = NULL;
    return NSTACKX_EFAILED;
}

static void DFileSenderDestory(DFileSession *session)
{
    CloseSocket(session->socket[0]);
    CloseSocket(session->socket[1]);
    session->socket[0] = NULL;
    session->socket[1] = NULL;

    List *pos = NULL;
    List *tmp = NULL;
    LIST_FOR_EACH_SAFE(pos, tmp, &session->peerInfoChain) {
        PeerInfo *peerInfo = (PeerInfo *)pos;
        ListRemoveNode(&peerInfo->list);
        free(peerInfo);
        session->peerInfoCnt--;
    }
}

static inline void InitSockaddr(const struct sockaddr_in *inSockAddr, struct sockaddr_in *sockAddr)
{
    (void)memset_s(sockAddr, sizeof(*sockAddr), 0, sizeof(*sockAddr));
    sockAddr->sin_family = AF_INET;
    sockAddr->sin_port = htons(inSockAddr->sin_port);
    sockAddr->sin_addr.s_addr = htonl(inSockAddr->sin_addr.s_addr);
}

static uint16_t GetClientSendThreadNum(uint16_t connType)
{
    if (connType == CONNECT_TYPE_WLAN) {
        return NSTACKX_WLAN_CLIENT_SEND_THREAD_NUM;
    } else {
        return 1;
    }
}

static int32_t CheckSessionPara(NSTACKX_SessionPara *sessionPara)
{
    if (sessionPara == NULL) {
        return NSTACKX_EFAILED;
    }

    if (sessionPara->addr == NULL ||
        sessionPara->addr->sin_family != AF_INET ||
        sessionPara->addrLen != sizeof(struct sockaddr_in)) {
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

void SendSettingToServer(DFileSession *session)
{
    List *pos = NULL;
    PeerInfo *peerInfo = NULL;
    LIST_FOR_EACH(pos, &session->peerInfoChain) {
        peerInfo = (PeerInfo *)pos;
        peerInfo->state = SETTING_NEGOTIATING;
        DFileSessionSendSetting(peerInfo);
    }
}

int32_t NSTACKX_DFileClientWithTargetDev(NSTACKX_SessionPara *para)
{
    /* EaglEye test */
    Coverity_Tainted_Set((void *)para);

    DFILE_LOGI(TAG, "begin to Create Dfile client");
    struct sockaddr_in sockAddr;

    if (CheckSessionPara(para) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    InitSockaddr(para->addr, &sockAddr);

    if (SocketModuleInit() != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    if (CongModuleInit() != NSTACKX_EOK) {
        goto L_ERR_CONG;
    }
    DFileSession *session = DFileSessionCreate(DFILE_SESSION_TYPE_CLIENT, para->msgReceiver);
    if (session == NULL) {
        goto L_ERR_SESSION;
    }
    uint16_t type = CONNECT_TYPE_NONE;
    if (DFileSenderInitWithTargetDev(session, &sockAddr, &type, para->localInterfaceName, 0) != NSTACKX_EOK) {
        goto L_ERR_SENDER_INIT;
    }

    if (CreateFileManager(session, para->key, para->keyLen, NSTACKX_TRUE, type) != NSTACKX_EOK) {
        goto L_ERR_FILE_MANAGER;
    }

    if (StartSessionRunning(session, GetClientSendThreadNum(type)) != NSTACKX_EOK) {
        goto L_ERR_THREAD;
    }

    SendSettingToServer(session);

    return session->sessionId;
L_ERR_THREAD:
    StopFileManagerThreads(session->fileManager);
    FileManagerDestroy(session->fileManager);
L_ERR_FILE_MANAGER:
    DFileSenderDestory(session);
L_ERR_SENDER_INIT:
    DFileSessionClean(session);
L_ERR_SESSION:
    CongModuleClean();
L_ERR_CONG:
    SocketModuleClean();
    DFILE_LOGE(TAG, "fail to create dfile client");
    return NSTACKX_EFAILED;
}

int32_t NSTACKX_DFileClient(struct sockaddr_in *srvAddr, socklen_t addrLen, const uint8_t *key, uint32_t keyLen,
                            DFileMsgReceiver msgReceiver)
{
    /* EaglEye test */
    Coverity_Tainted_Set((void *)srvAddr);
    Coverity_Tainted_Set((void *)&addrLen);
    Coverity_Tainted_Set((void *)key);
    Coverity_Tainted_Set((void *)&keyLen);
    Coverity_Tainted_Set((void *)msgReceiver);

    NSTACKX_SessionPara sessionPara;

    (void)memset_s(&sessionPara, sizeof(sessionPara), 0, sizeof(sessionPara));
    sessionPara.addr = srvAddr;
    sessionPara.addrLen = addrLen;
    sessionPara.key = key;
    sessionPara.keyLen = keyLen;
    sessionPara.msgReceiver = msgReceiver;
    sessionPara.localInterfaceName = NULL;
#ifdef NSTACKX_WITH_LITEOS
    EpollEventPtrInit();
#endif
    return NSTACKX_DFileClientWithTargetDev(&sessionPara);
}

static inline void ClearPendingFileList(DFileSession *session)
{
    List *tmp = NULL;
    List *pos = NULL;
    LIST_FOR_EACH_SAFE(pos, tmp, &session->pendingFileLists) {
        FileListInfo *fileListInfo = (FileListInfo *)pos;
        ListRemoveNode(&fileListInfo->list);
        DestroyFileListInfo(fileListInfo);
    }
}

#ifdef NSTACKX_SMALL_FILE_SUPPORT
static inline void ClearSmallFileList(DFileSession *session)
{
    List *tmp = NULL;
    List *pos = NULL;
    LIST_FOR_EACH_SAFE(pos, tmp, &session->smallFileLists) {
        FileListInfo *fileListInfo = (FileListInfo *)pos;
        ListRemoveNode(&fileListInfo->list);
        DestroyFileListInfo(fileListInfo);
    }
}
#endif

static inline void ClearTransChain(DFileSession *session)
{
    while (!ListIsEmpty(&session->dFileTransChain)) {
        DFileTrans *trans = (DFileTrans *)ListPopFront(&session->dFileTransChain);
        DFileTransDestroy(trans);
    }
}

static inline void ClearOutboundQueue(DFileSession *session)
{
    List *tmp = NULL;
    List *pos = NULL;
    LIST_FOR_EACH_SAFE(pos, tmp, &session->outboundQueue) {
        QueueNode *node = (QueueNode *)pos;
        ListRemoveNode(&node->list);
        free(node->frame);
        free(node);
    }
}

static inline void ClearInboundQueue(DFileSession *session)
{
    List *tmp = NULL;
    List *pos = NULL;
    LIST_FOR_EACH_SAFE(pos, tmp, &session->inboundQueue) {
        QueueNode *node = (QueueNode *)pos;
        ListRemoveNode(&node->list);
        free(node->frame);
        free(node);
    }
}


void NSTACKX_DFileClose(int32_t sessionId)
{
    /* EaglEye test */
    Coverity_Tainted_Set((void *)&sessionId);

    DFILE_LOGI(TAG, "begin to close session");
    if (CheckSessionIdValid(sessionId) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "invalid session id (%d) for close", sessionId);
        return;
    }

    DFileSessionNode *sessionNode = PopDFileSessionNodeById((uint16_t)sessionId);
    if (CheckDFileSessionNodeValid(sessionNode) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "no session found for id %d", sessionId);
        return;
    }

    StopDFileThreads(sessionNode->session);
    ClearPendingFileList(sessionNode->session);
#ifdef NSTACKX_SMALL_FILE_SUPPORT
    ClearSmallFileList(sessionNode->session);
#endif
    ClearTransChain(sessionNode->session);
    ClearOutboundQueue(sessionNode->session);
    ClearInboundQueue(sessionNode->session);
    ClearTransStateList(sessionNode->session);
    FileManagerDestroy(sessionNode->session->fileManager);
    CloseSocket(sessionNode->session->socket[0]);
    CloseSocket(sessionNode->session->socket[1]);
    if (sessionNode->session->sessionType == DFILE_SESSION_TYPE_SERVER) {
        if (sessionNode->session->acceptSocket != NULL) {
            CloseSocket(sessionNode->session->acceptSocket);
        }
    }

    DFileSessionClean(sessionNode->session);
    free(sessionNode);
    CongModuleClean();
    SocketModuleClean();
    DFILE_LOGI(TAG, "finish to close session");
}

static void DFileSetRenameHookInner(void *arg)
{
    DFileSetRenameHookCtx *ctx = arg;
    if (ctx->session == NULL) {
        free(ctx);
        return;
    }
    ctx->session->onRenameFile = ctx->onRenameFile;
    free(ctx);
}

int32_t NSTACKX_DFileSetRenameHook(int32_t sessionId, OnDFileRenameFile onRenameFile)
{
    /* EaglEye test */
    Coverity_Tainted_Set((void *)&sessionId);
    Coverity_Tainted_Set((void *)onRenameFile);
    DFileSetRenameHookCtx *ctx = NULL;

    if (CheckSessionIdValid(sessionId) != NSTACKX_EOK || onRenameFile == NULL) {
        DFILE_LOGE(TAG, "invalid arg input");
        return NSTACKX_EINVAL;
    }

    DFileSessionNode *node = GetDFileSessionNodeById((uint16_t)sessionId);
    if (CheckDFileSessionNodeValid(node) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "no session found for id %d", sessionId);
        return NSTACKX_EINVAL;
    }

    ctx = malloc(sizeof(DFileSetRenameHookCtx));
    if (ctx == NULL) {
        return NSTACKX_ENOMEM;
    }
    ctx->session = node->session;
    ctx->onRenameFile = onRenameFile;

    if (PostEvent(&node->session->eventNodeChain, node->session->epollfd, DFileSetRenameHookInner, ctx) !=
        NSTACKX_EOK) {
        free(ctx);
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

static DFileLogImpl g_userLogImpl;

static void LogWrapper(const char *tag, uint32_t level, const char *format, va_list args)
{
    if (g_userLogImpl) {
        g_userLogImpl(tag, level, format, args);
    }
}

int32_t NSTACKX_DFileRegisterLog(DFileLogImpl logImpl)
{
    if (logImpl == NULL) {
        (void)printf("NULL pointer\n");
        return NSTACKX_EFAILED;
    }
    g_userLogImpl = logImpl;
    SetLogImpl(LogWrapper);
    return NSTACKX_EOK;
}

uint32_t NSTACKX_DFileGetCapabilities(void)
{
    return g_capabilities;
}

int32_t NSTACKX_DFileSetCapabilities(uint32_t capabilities, uint32_t value)
{
    /* EaglEye test */
    Coverity_Tainted_Set((void *)&capabilities);
    Coverity_Tainted_Set((void *)&value);

    /* unused para */
    (void)(capabilities);
    (void)(value);
    return NSTACKX_EOK;
}

#ifdef DFILE_ENABLE_HIDUMP
int32_t NSTACKX_DFileDump(uint32_t argc, const char **arg, void *softObj, DFileDumpFunc dump)
{
    int32_t ret = 0, c = 0;
    char *message = NULL;
    char *opt = NULL;
    size_t size = 0;
    message = (char *)malloc(DUMP_INFO_MAX * sizeof(char));
    if (message == NULL) {
        DFILE_LOGE(TAG, "malloc failed");
        return NSTACKX_EFAILED;
    }
    (void)memset_s(message, DUMP_INFO_MAX, 0, DUMP_INFO_MAX);

    NstackGetOptMsg optMsg;
    (void)NstackInitGetOptMsg(&optMsg);

    while ((c = NstackGetOpt(&optMsg, argc, arg, "s:m:hl")) != NSTACK_GETOPT_END_OF_STR) {
        switch (c) {
            case 'h':
                ret = HidumpHelp(message, &size);
                break;
            case 'l':
                ret = HidumpList(message, &size);
                break;
            case 'm':
                opt = (char *)NstackGetOptArgs(&optMsg);
                ret = HidumpMessage(message, &size, opt);
                break;
            case 's':
                opt = (char *)NstackGetOptArgs(&optMsg);
                ret = HidumpInformation(message, &size, opt);
                break;
            default:
                DFILE_LOGE(TAG, "unknown option");
                ret = HidumpHelp(message, &size);
                break;
        }
        if (ret != NSTACKX_EOK) {
            free(message);
            return ret;
        }
        dump(softObj, message, size);
        (void)memset_s(message, DUMP_INFO_MAX, 0, DUMP_INFO_MAX);
    }
    free(message);
    return ret;
}
#endif

void NSTACKX_DFileSetEventFunc(void *softObj, DFileEventFunc func)
{
    DFileSetEvent(softObj, func);
}

int32_t NSTACKX_DFileRegisterLogCallback(DFileLogCallback userLogCallback)
{
    if (userLogCallback == NULL) {
        DFILE_LOGE(TAG, "logImpl null");
        return NSTACKX_EFAILED;
    }
    int32_t ret = SetLogCallback(userLogCallback);
    return ret;
}

void NSTACKX_DFileRegisterDefaultLog(void)
{
    SetDefaultLogCallback();
    return;
}

int32_t NSTACKX_DFileSessionGetFileList(int32_t sessionId)
{
    return NSTACKX_EOK;
}

int32_t NSTACKX_DFileSetSessionOpt(int32_t sessionId, const DFileOpt *opt)
{
    return NSTACKX_EOK;
}