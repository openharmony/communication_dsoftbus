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

#include "client_trans_file_listener.h"

#include <securec.h>

#include "anonymizer.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "trans_log.h"

static SoftBusList *g_fileListener = NULL;

int TransFileInit(void)
{
    if (g_fileListener != NULL) {
        TRANS_LOGI(TRANS_INIT, "file listener has init.");
        return SOFTBUS_OK;
    }
    g_fileListener = CreateSoftBusList();
    if (g_fileListener == NULL) {
        TRANS_LOGE(TRANS_INIT, "create file listener list failed.");
        return SOFTBUS_MALLOC_ERR;
    }
    return SOFTBUS_OK;
}

void TransFileDeinit(void)
{
    if (g_fileListener == NULL) {
        return;
    }
    if (SoftBusMutexLock(&(g_fileListener->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "file listener deinit lock failed");
        return;
    }
    FileListener *fileNode = NULL;
    FileListener *nextNode = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(fileNode, nextNode, &(g_fileListener->list), FileListener, node) {
        ListDelete(&(fileNode->node));
        SoftBusFree(fileNode);
    }
    (void)SoftBusMutexUnlock(&(g_fileListener->lock));
    DestroySoftBusList(g_fileListener);
    g_fileListener = NULL;
}

int32_t TransSetFileReceiveListener(const char *sessionName,
    const IFileReceiveListener *recvListener, const char *rootDir)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_fileListener != NULL, SOFTBUS_TRANS_FILE_LISTENER_NOT_INIT, TRANS_CTRL, "file listener hasn't init.");
    if (SoftBusMutexLock(&(g_fileListener->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "file receive listener lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    FileListener *fileNode = NULL;
    bool exist = false;
    LIST_FOR_EACH_ENTRY(fileNode, &(g_fileListener->list), FileListener, node) {
        if (strcmp(fileNode->mySessionName, sessionName) == 0) {
            exist = true;
            break;
        }
    }
    if (exist) {
        if (strcpy_s(fileNode->rootDir, FILE_RECV_ROOT_DIR_SIZE_MAX, rootDir) != EOK ||
            memcpy_s(&(fileNode->recvListener), sizeof(IFileReceiveListener),
                recvListener, sizeof(IFileReceiveListener)) != EOK) {
            (void)SoftBusMutexUnlock(&(g_fileListener->lock));
            TRANS_LOGE(TRANS_FILE, "update file receive listener failed");
            return SOFTBUS_MEM_ERR;
        }
        (void)SoftBusMutexUnlock(&(g_fileListener->lock));
        TRANS_LOGI(TRANS_FILE, "update file receive listener success");
        return SOFTBUS_OK;
    }
    fileNode = (FileListener *)SoftBusCalloc(sizeof(FileListener));
    if (fileNode == NULL) {
        (void)SoftBusMutexUnlock(&(g_fileListener->lock));
        TRANS_LOGE(TRANS_FILE, "file receive listener calloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(fileNode->mySessionName, SESSION_NAME_SIZE_MAX, sessionName) != EOK ||
        strcpy_s(fileNode->rootDir, FILE_RECV_ROOT_DIR_SIZE_MAX, rootDir) != EOK ||
        memcpy_s(&(fileNode->recvListener), sizeof(IFileReceiveListener),
            recvListener, sizeof(IFileReceiveListener)) != EOK) {
        TRANS_LOGE(TRANS_FILE, "file node copy failed.");
        SoftBusFree(fileNode);
        (void)SoftBusMutexUnlock(&(g_fileListener->lock));
        return SOFTBUS_MEM_ERR;
    }
    ListAdd(&(g_fileListener->list), &(fileNode->node));
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGI(TRANS_FILE, "add sessionName=%{public}s", AnonymizeWrapper(tmpName));
    AnonymizeFree(tmpName);
    (void)SoftBusMutexUnlock(&(g_fileListener->lock));
    return SOFTBUS_OK;
}

int32_t TransSetFileSendListener(const char *sessionName, const IFileSendListener *sendListener)
{
    if (g_fileListener == NULL) {
        TRANS_LOGE(TRANS_FILE, "file listener hasn't init.");
        return SOFTBUS_TRANS_FILE_LISTENER_NOT_INIT;
    }
    if (SoftBusMutexLock(&(g_fileListener->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "file send listener lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    FileListener *fileNode = NULL;
    bool exist = false;
    LIST_FOR_EACH_ENTRY(fileNode, &(g_fileListener->list), FileListener, node) {
        if (strcmp(fileNode->mySessionName, sessionName) == 0) {
            exist = true;
            break;
        }
    }
    if (exist) {
        if (memcpy_s(&(fileNode->sendListener), sizeof(IFileSendListener),
            sendListener, sizeof(IFileSendListener)) != EOK) {
            (void)SoftBusMutexUnlock(&(g_fileListener->lock));
            TRANS_LOGE(TRANS_FILE, "memcpy_s file send listener failed");
            return SOFTBUS_MEM_ERR;
        }
        (void)SoftBusMutexUnlock(&(g_fileListener->lock));
        TRANS_LOGE(TRANS_FILE, "update file send listener success");
        return SOFTBUS_OK;
    }
    fileNode = (FileListener *)SoftBusCalloc(sizeof(FileListener));
    if (fileNode == NULL) {
        (void)SoftBusMutexUnlock(&(g_fileListener->lock));
        TRANS_LOGE(TRANS_FILE, "file send listener calloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(fileNode->mySessionName, SESSION_NAME_SIZE_MAX, sessionName) != EOK ||
        memcpy_s(&(fileNode->sendListener), sizeof(IFileSendListener),
            sendListener, sizeof(IFileSendListener)) != EOK) {
        TRANS_LOGE(TRANS_FILE, "file node copy failed.");
        SoftBusFree(fileNode);
        (void)SoftBusMutexUnlock(&(g_fileListener->lock));
        return SOFTBUS_MEM_ERR;
    }
    ListAdd(&(g_fileListener->list), &(fileNode->node));
    TRANS_LOGI(TRANS_FILE, "add sessionName = %{public}s", sessionName);
    (void)SoftBusMutexUnlock(&(g_fileListener->lock));
    return SOFTBUS_OK;
}

static int32_t TransAddNewSocketFileListener(const char *sessionName, SocketFileCallbackFunc fileCallback,
    bool isReceiver)
{
    if (sessionName == NULL || fileCallback == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    FileListener *listener = (FileListener *)SoftBusCalloc(sizeof(FileListener));
    if (listener == NULL) {
        TRANS_LOGE(TRANS_SDK, "file send listener calloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(listener->mySessionName, SESSION_NAME_SIZE_MAX, sessionName) != EOK) {
        TRANS_LOGE(TRANS_SDK, "file node copy failed.");
        SoftBusFree(listener);
        return SOFTBUS_STRCPY_ERR;
    }
    if (isReceiver) {
        listener->socketRecvCallback = fileCallback;
    } else {
        listener->socketSendCallback = fileCallback;
    }
    ListAdd(&(g_fileListener->list), &(listener->node));
    return SOFTBUS_OK;
}

int32_t TransSetSocketFileListener(const char *sessionName, SocketFileCallbackFunc fileCallback, bool isReceiver)
{
    if (sessionName == NULL || fileCallback == NULL) {
        TRANS_LOGE(TRANS_SDK, "[client] invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_fileListener == NULL) {
        TRANS_LOGE(TRANS_FILE, "file listener hasn't init.");
        return SOFTBUS_TRANS_FILE_LISTENER_NOT_INIT;
    }
    if (SoftBusMutexLock(&(g_fileListener->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "file delete lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    FileListener *fileNode = NULL;
    bool exist = false;
    LIST_FOR_EACH_ENTRY(fileNode, &(g_fileListener->list), FileListener, node) {
        if (strcmp(fileNode->mySessionName, sessionName) == 0) {
            exist = true;
            break;
        }
    }
    if (exist) {
        if (isReceiver) {
            fileNode->socketRecvCallback = fileCallback;
        } else {
            fileNode->socketSendCallback = fileCallback;
        }
        (void)SoftBusMutexUnlock(&(g_fileListener->lock));
        TRANS_LOGI(TRANS_SDK, "update file callback of socket");
        return SOFTBUS_OK;
    }
    int32_t ret = TransAddNewSocketFileListener(sessionName, fileCallback, isReceiver);
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_fileListener->lock));
        TRANS_LOGE(TRANS_SDK, "failed to add new socket file listener");
        return ret;
    }
    (void)SoftBusMutexUnlock(&(g_fileListener->lock));

    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGI(TRANS_SDK, "set socket file listener ok, sessionName=%{public}s, isReceiver=%{public}d",
        AnonymizeWrapper(tmpName), isReceiver);
    AnonymizeFree(tmpName);
    return SOFTBUS_OK;
}

int32_t TransGetFileListener(const char *sessionName, FileListener *fileListener)
{
    if (g_fileListener == NULL) {
        TRANS_LOGE(TRANS_FILE, "file listener hasn't init.");
        return SOFTBUS_TRANS_FILE_LISTENER_NOT_INIT;
    }
    if (SoftBusMutexLock(&(g_fileListener->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "file get listener lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    FileListener *fileNode = NULL;
    LIST_FOR_EACH_ENTRY(fileNode, &(g_fileListener->list), FileListener, node) {
        if (strcmp(fileNode->mySessionName, sessionName) == 0) {
            if (memcpy_s(fileListener, sizeof(FileListener), fileNode, sizeof(FileListener)) != EOK) {
                TRANS_LOGE(TRANS_FILE, "memcpy_s file listener failed.");
                (void)SoftBusMutexUnlock(&(g_fileListener->lock));
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&(g_fileListener->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_fileListener->lock));
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

void TransDeleteFileListener(const char *sessionName)
{
    if (sessionName == NULL) {
        TRANS_LOGW(TRANS_FILE, "invalid param.");
        return;
    }
    if (g_fileListener == NULL) {
        TRANS_LOGE(TRANS_FILE, "file listener hasn't init.");
        return;
    }
    if (SoftBusMutexLock(&(g_fileListener->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "file delete lock failed");
        return;
    }

    FileListener *fileNode = NULL;
    LIST_FOR_EACH_ENTRY(fileNode, &(g_fileListener->list), FileListener, node) {
        if (strcmp(fileNode->mySessionName, sessionName) == 0) {
            ListDelete(&fileNode->node);
            char *tmpName = NULL;
            Anonymize(sessionName, &tmpName);
            TRANS_LOGI(TRANS_FILE, "delete sessionName=%{public}s", AnonymizeWrapper(tmpName));
            AnonymizeFree(tmpName);
            SoftBusFree(fileNode);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&(g_fileListener->lock));
}
