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

#include "nstackx_dfile_dfx.h"
#include "securec.h"
#include "nstackx_dfile_session.h"
#include "nstackx_dfile_transfer.h"
#include "nstackx_dfile_log.h"

#define TAG "nStackXDFile"
#ifdef DFILE_ENABLE_HIDUMP

static bool g_dfileDumpFrameSwitch = 0;

int32_t HidumpHelp(char *message, size_t *size)
{
    int32_t ret = 0;
    ret = sprintf_s(message, DUMP_INFO_MAX,
        "\n-h   help information about the hidump dfile command.\n"
        "-l   Displays all session IDs.\n"
        "-m   signaling packet switch, 1:open, 0:close.\n"
        "-s   Displays information about the transmit end/receive end.\n"
        "     transmit end: capability, sending rate, I/O rate, send block number.\n"
        "     receive end: capability, I/O rate, retransmissions number, recev number, total number\n");
    if (ret == -1) {
        DFILE_LOGE(TAG, "write message failed");
        return NSTACKX_EFAILED;
    }

    *size = strlen(message);
    return NSTACKX_EOK;
}

int32_t HidumpList(char *message, size_t *size)
{
    int32_t ret = 0, retTemp = 0;
    uint16_t count = 0;
    bool flag = 0;
    DFileSessionNode *node = NULL;
    if (PthreadMutexLock(&g_dFileSessionChainMutex) != 0) {
        DFILE_LOGE(TAG, "lock g_dFileSessionChainMutex failed");
        return 0;
    }
    List *pos = NULL;
    retTemp = sprintf_s(message + ret, DUMP_INFO_MAX - ret, "\nsession id list:\n");
    retTemp == -1 ? (flag = 1) : (ret = ret + retTemp);
    LIST_FOR_EACH(pos, &g_dFileSessionChain)
    {
        node = (DFileSessionNode *)pos;
        retTemp = sprintf_s(message + ret, DUMP_INFO_MAX - ret, "index %u sessionId: %u \n", count, node->sessionId);
        retTemp == -1 ? (flag = 1) : (ret = ret + retTemp);
        count++;
    }

    if (PthreadMutexUnlock(&g_dFileSessionChainMutex) != 0) {
        DFILE_LOGE(TAG, "unlock g_dFileSessionChainMutex failed");
        return 0;
    }
    *size = strlen(message);

    if (flag == 1) {
        DFILE_LOGE(TAG, "write message failed");
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

static int32_t HidumpInfoClient(char *message, size_t *size, DFileSession *session)
{
    int32_t ret = 0, retTemp = 0;
    bool flag = 0;
    List *pos = NULL;
    PeerInfo *peerInfoTemp = NULL;

    retTemp = sprintf_s(message + ret, DUMP_INFO_MAX - ret, "\ncapability: %x\n", session->capability);
    retTemp == -1 ? (flag = 1) : (ret = ret + retTemp);
    retTemp = sprintf_s(message + ret, DUMP_INFO_MAX - ret, "amendSendRate: ");
    retTemp == -1 ? (flag = 1) : (ret = ret + retTemp);
    LIST_FOR_EACH(pos, &session->peerInfoChain)
    {
        peerInfoTemp = (PeerInfo *)pos;
        retTemp = sprintf_s(message + ret, DUMP_INFO_MAX - ret, "%d ", peerInfoTemp->amendSendRate);
        retTemp == -1 ? (flag = 1) : (ret = ret + retTemp);
    }
    retTemp = sprintf_s(message + ret, DUMP_INFO_MAX - ret, "\nIO read rate: %u KB/s\n", session->fileManager->iorRate);
    retTemp == -1 ? (flag = 1) : (ret = ret + retTemp);
    retTemp = sprintf_s(message + ret, DUMP_INFO_MAX - ret, "total send block num: %llu\n",
        NSTACKX_ATOM_FETCH(&(session->totalSendBlocks)));
    retTemp == -1 ? (flag = 1) : (ret = ret + retTemp);

    *size = strlen(message);

    if (flag == 1) {
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

static int32_t HidumpInfoServer(char *message, size_t *size, DFileSession *session)
{
    int32_t ret = 0, retTemp = 0;
    bool flag = 0;
    List *pos = NULL;
    DFileTrans *transTemp = NULL;

    retTemp = sprintf_s(message + ret, DUMP_INFO_MAX - ret, "\ncapability: %x\n", session->capability);
    retTemp == -1 ? (flag = 1) : (ret = ret + retTemp);
    retTemp = sprintf_s(message + ret, DUMP_INFO_MAX - ret, "IO write rate: %u KB/s\n", session->fileManager->iowRate);
    retTemp == -1 ? (flag = 1) : (ret = ret + retTemp);
    LIST_FOR_EACH(pos, &session->dFileTransChain)
    {
        transTemp = (DFileTrans *)pos;
        retTemp = sprintf_s(message + ret, DUMP_INFO_MAX - ret, "trans id: %d\n", transTemp->transId);
        retTemp == -1 ? (flag = 1) : (ret = ret + retTemp);
        retTemp = sprintf_s(message + ret, DUMP_INFO_MAX - ret, "allRetrySendCount:%u recev:%d all:%llu\n",
            transTemp->allRetrySendCount, transTemp->receivedDataFrameCnt, transTemp->totalDataFrameCnt);
        retTemp == -1 ? (flag = 1) : (ret = ret + retTemp);
    }

    *size = strlen(message);

    if (flag == 1) {
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

int32_t HidumpInformation(char *message, size_t *size, char *opt)
{
    int32_t ret = 0;
    int64_t sessionId = 0;
    DFileSession *session = NULL;
    DFileSessionNode *node = NULL;

    sessionId = (int64_t)strtol(opt, NULL, DUMP_DECIMAL);
    if (sessionId > USHRT_MAX) {
        (void)sprintf_s(message, DUMP_INFO_MAX, "session id is overflowing");
        *size = strlen(message);
        return NSTACKX_EOK;
    }

    node = GetDFileSessionNodeById(sessionId);
    if (node == NULL) {
        ret = sprintf_s(message, DUMP_INFO_MAX, "find session by session id failed");
        return NSTACKX_EOK;
    }

    session = node->session;

    if (session->sessionType == DFILE_SESSION_TYPE_CLIENT) {
        ret = HidumpInfoClient(message, size, session);
    } else {
        ret = HidumpInfoServer(message, size, session);
    }

    if (ret != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "write message failed");
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

static void SetDfileDumpFrameSwitch(bool status)
{
    g_dfileDumpFrameSwitch = status;
}

bool GetDfileDumpFrameSwitch()
{
    return g_dfileDumpFrameSwitch;
}

int32_t HidumpMessage(char *message, size_t *size, char *opt)
{
    int ret = 0;
    int64_t input;
    input = (int64_t)strtol(opt, NULL, DUMP_DECIMAL);
    if (input == 1) {
        SetDfileDumpFrameSwitch(1);
        ret = sprintf_s(message, DUMP_INFO_MAX, "Signaling packet switch is open");
    } else if (input == 0) {
        SetDfileDumpFrameSwitch(0);
        ret = sprintf_s(message, DUMP_INFO_MAX, "Signaling packet switch is close");
    } else {
        ret = sprintf_s(message, DUMP_INFO_MAX, "Invalid input");
    }
    if (ret == -1) {
        DFILE_LOGE(TAG, "write message failed");
        return NSTACKX_EFAILED;
    }

    *size = strlen(message);
    return NSTACKX_EOK;
}
#endif

static void EventAssemble(char *eventName, DFileEventType eventType, DFileEventLevel eventLevel, uint32_t eventNum,
    DFileEventParam *transParam)
{
    DFileEvent temp;
    DFileEvent *msg = &temp;
    if (strcpy_s(msg->eventName, DFile_EVENT_NAME_LEN, eventName) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "string copy failed", 0);
        return;
    }
    msg->type = eventType;
    msg->level = eventLevel;
    msg->paramNum = eventNum;
    msg->params = transParam;
    NSTACKX_DFileAssembleFunc(NULL, msg);
}

void WaitFileHeaderTimeoutEvent(DFileTransErrorCode errorCode)
{
    char valueStr[DFile_EVENT_NAME_LEN];
    char eventName[DFile_EVENT_NAME_LEN] = "Header confirm timeout";

    DFileEventParam temp;
    DFileEventParam *transParam = &temp;
    (void)sprintf_s(valueStr, DFile_EVENT_NAME_LEN, "Errorcode: %u", errorCode);
    transParam->type = DFile_PARAM_TYPE_STRING;

    if (strcpy_s(transParam->name, DFile_EVENT_NAME_LEN, "ERROR_CODE") != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "string copy failed");
        return;
    }
    if (strcpy_s(transParam->value.str, DFile_EVENT_NAME_LEN, valueStr) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "string copy failed");
        return;
    }

    EventAssemble(eventName, DFile_EVENT_TYPE_FAULT, DFile_EVENT_LEVEL_CRITICAL, 1, transParam);
}

void DFileServerCreateEvent(void)
{
    char valueStr[DFile_EVENT_NAME_LEN] = "";
    char eventName[DFile_EVENT_NAME_LEN] = "Server created";

    DFileEventParam temp;
    DFileEventParam *transParam = &temp;
    transParam->type = DFile_PARAM_TYPE_STRING;

    if (strcpy_s(transParam->name, DFile_EVENT_NAME_LEN, "NA") != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "string copy failed");
        return;
    }
    if (strcpy_s(transParam->value.str, DFile_EVENT_NAME_LEN, valueStr) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "string copy failed");
        return;
    }

    EventAssemble(eventName, DFile_EVENT_TYPE_BEHAVIOR, DFile_EVENT_LEVEL_MINOR, 0, transParam);
}

void DFileClientCreateEvent(void)
{
    char valueStr[DFile_EVENT_NAME_LEN];
    char eventName[DFile_EVENT_NAME_LEN] = "Client created";

    DFileEventParam temp;
    DFileEventParam *transParam = &temp;
    (void)sprintf_s(valueStr, DFile_EVENT_NAME_LEN, "");
    transParam->type = DFile_PARAM_TYPE_STRING;

    if (strcpy_s(transParam->name, DFile_EVENT_NAME_LEN, "NA") != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "string copy failed");
        return;
    }
    if (strcpy_s(transParam->value.str, DFile_EVENT_NAME_LEN, valueStr) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "string copy failed");
        return;
    }

    EventAssemble(eventName, DFile_EVENT_TYPE_BEHAVIOR, DFile_EVENT_LEVEL_MINOR, 0, transParam);
}

void DFileSendFileBeginEvent(void)
{
    char valueStr[DFile_EVENT_NAME_LEN];
    char eventName[DFile_EVENT_NAME_LEN] = "Send file begin";

    DFileEventParam temp;
    DFileEventParam *transParam = &temp;
    (void)sprintf_s(valueStr, DFile_EVENT_NAME_LEN, "");
    transParam->type = DFile_PARAM_TYPE_STRING;

    if (strcpy_s(transParam->name, DFile_EVENT_NAME_LEN, "NA") != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "string copy failed", 0);
        return;
    }
    if (strcpy_s(transParam->value.str, DFile_EVENT_NAME_LEN, valueStr) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "string copy failed", 0);
        return;
    }

    EventAssemble(eventName, DFile_EVENT_TYPE_BEHAVIOR, DFile_EVENT_LEVEL_MINOR, 0, transParam);
}

void PeerShuttedEvent(void)
{
    char valueStr[DFile_EVENT_NAME_LEN];
    char eventName[DFile_EVENT_NAME_LEN] = "Peer shutted down";

    DFileEventParam temp;
    DFileEventParam *transParam = &temp;
    (void)sprintf_s(valueStr, DFile_EVENT_NAME_LEN, "");
    transParam->type = DFile_PARAM_TYPE_STRING;

    if (strcpy_s(transParam->name, DFile_EVENT_NAME_LEN, "SocketIndex") != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "string copy failed", 0);
        return;
    }
    if (strcpy_s(transParam->value.str, DFile_EVENT_NAME_LEN, valueStr) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "string copy failed", 0);
        return;
    }

    EventAssemble(eventName, DFile_EVENT_TYPE_FAULT, DFile_EVENT_LEVEL_CRITICAL, 1, transParam);
}

void TransferCompleteEvent(const double rate)
{
    char valueStr[DFile_EVENT_NAME_LEN];
    char eventName[DFile_EVENT_NAME_LEN] = "transferring completed";

    DFileEventParam temp;
    DFileEventParam *transParam = &temp;
    (void)sprintf_s(valueStr, DFile_EVENT_NAME_LEN, "rate: %.2f MB/s", rate);
    transParam->type = DFile_PARAM_TYPE_STRING;

    if (strcpy_s(transParam->name, DFile_EVENT_NAME_LEN, "TRANSRATE") != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "string copy failed", 0);
        return;
    }
    if (strcpy_s(transParam->value.str, DFile_EVENT_NAME_LEN, valueStr) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "string copy failed", 0);
        return;
    }

    EventAssemble(eventName, DFile_EVENT_TYPE_STATISTIC, DFile_EVENT_LEVEL_MINOR, 0, transParam);
}

void AcceptSocketEvent(void)
{
    char valueStr[DFile_EVENT_NAME_LEN];
    char eventName[DFile_EVENT_NAME_LEN] = "Accept socket success";

    DFileEventParam temp;
    DFileEventParam *transParam = &temp;
    (void)sprintf_s(valueStr, DFile_EVENT_NAME_LEN, "");
    transParam->type = DFile_PARAM_TYPE_STRING;

    if (strcpy_s(transParam->name, DFile_EVENT_NAME_LEN, "NA") != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "string copy failed", 0);
        return;
    }
    if (strcpy_s(transParam->value.str, DFile_EVENT_NAME_LEN, valueStr) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "string copy failed", 0);
        return;
    }

    EventAssemble(eventName, DFile_EVENT_TYPE_BEHAVIOR, DFile_EVENT_LEVEL_MINOR, 0, transParam);
}
