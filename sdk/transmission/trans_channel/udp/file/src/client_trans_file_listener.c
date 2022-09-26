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

#include "client_trans_file_listener.h"

#include <securec.h>

#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

static SoftBusList *g_fileListener = NULL;

int TransFileInit(void)
{
    if (g_fileListener != NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "file listener has initialized.");
        return SOFTBUS_OK;
    }
    g_fileListener = CreateSoftBusList();
    if (g_fileListener == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create file listener list failed.");
        return SOFTBUS_MALLOC_ERR;
    }
    return SOFTBUS_OK;
}

void TransFileDeinit(void)
{
    if (g_fileListener == NULL) {
        return;
    }
    if (SoftBusMutexLock(&(g_fileListener->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file listener deinit lock failed");
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
    if (g_fileListener == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file listener hasn't initialized.");
        return SOFTBUS_TRANS_FILE_LISTENER_NOT_INIT;
    }
    if (SoftBusMutexLock(&(g_fileListener->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file receive listener lock failed");
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
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "update file receive listener failed");
            return SOFTBUS_ERR;
        }
        (void)SoftBusMutexUnlock(&(g_fileListener->lock));
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "update file receive listener success");
        return SOFTBUS_OK;
    }
    fileNode = (FileListener *)SoftBusCalloc(sizeof(FileListener));
    if (fileNode == NULL) {
        (void)SoftBusMutexUnlock(&(g_fileListener->lock));
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file receive listener calloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(fileNode->mySessionName, SESSION_NAME_SIZE_MAX, sessionName) != EOK ||
        strcpy_s(fileNode->rootDir, FILE_RECV_ROOT_DIR_SIZE_MAX, rootDir) != EOK ||
        memcpy_s(&(fileNode->recvListener), sizeof(IFileReceiveListener),
            recvListener, sizeof(IFileReceiveListener)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file node copy failed.");
        SoftBusFree(fileNode);
        (void)SoftBusMutexUnlock(&(g_fileListener->lock));
        return SOFTBUS_ERR;
    }
    ListAdd(&(g_fileListener->list), &(fileNode->node));
    (void)SoftBusMutexUnlock(&(g_fileListener->lock));
    return SOFTBUS_OK;
}

int32_t TransSetFileSendListener(const char *sessionName, const IFileSendListener *sendListener)
{
    if (g_fileListener == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file listener hasn't initialized.");
        return SOFTBUS_TRANS_FILE_LISTENER_NOT_INIT;
    }
    if (SoftBusMutexLock(&(g_fileListener->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file send listener lock failed");
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
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "update file send listener failed");
            return SOFTBUS_ERR;
        }
        (void)SoftBusMutexUnlock(&(g_fileListener->lock));
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "update file send listener success");
        return SOFTBUS_OK;
    }
    fileNode = (FileListener *)SoftBusCalloc(sizeof(FileListener));
    if (fileNode == NULL) {
        (void)SoftBusMutexUnlock(&(g_fileListener->lock));
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file send listener calloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(fileNode->mySessionName, SESSION_NAME_SIZE_MAX, sessionName) != EOK ||
        memcpy_s(&(fileNode->sendListener), sizeof(IFileSendListener),
            sendListener, sizeof(IFileSendListener)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file node copy failed.");
        SoftBusFree(fileNode);
        (void)SoftBusMutexUnlock(&(g_fileListener->lock));
        return SOFTBUS_ERR;
    }
    ListAdd(&(g_fileListener->list), &(fileNode->node));
    (void)SoftBusMutexUnlock(&(g_fileListener->lock));
    return SOFTBUS_OK;
}

int32_t TransGetFileListener(const char *sessionName, FileListener *fileListener)
{
    if (g_fileListener == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file listener hasn't initialized.");
        return SOFTBUS_TRANS_FILE_LISTENER_NOT_INIT;
    }
    if (SoftBusMutexLock(&(g_fileListener->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file get listener lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    FileListener *fileNode = NULL;
    LIST_FOR_EACH_ENTRY(fileNode, &(g_fileListener->list), FileListener, node) {
        if (strcmp(fileNode->mySessionName, sessionName) == 0) {
            if (memcpy_s(fileListener, sizeof(FileListener), fileNode, sizeof(FileListener)) != EOK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy_s failed.");
                (void)SoftBusMutexUnlock(&(g_fileListener->lock));
                return SOFTBUS_ERR;
            }
            (void)SoftBusMutexUnlock(&(g_fileListener->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_fileListener->lock));
    return SOFTBUS_ERR;
}

void TransDeleteFileListener(const char *sessionName)
{
    if (sessionName == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[client]%s invalid param.", __func__);
        return;
    }
    if (g_fileListener == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file listener hasn't initialized.");
        return;
    }
    if (SoftBusMutexLock(&(g_fileListener->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file delete lock failed");
        return;
    }

    FileListener *fileNode = NULL;
    LIST_FOR_EACH_ENTRY(fileNode, &(g_fileListener->list), FileListener, node) {
        if (strcmp(fileNode->mySessionName, sessionName) == 0) {
            ListDelete(&fileNode->node);
            SoftBusFree(fileNode);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&(g_fileListener->lock));
}
