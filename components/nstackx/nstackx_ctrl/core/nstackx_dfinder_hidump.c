/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "nstackx_dfinder_hidump.h"
#include <inttypes.h>
#include "nstackx_dfinder_log.h"
#include "nstackx_dfinder_mgt_msg_log.h"
#include "nstackx_util.h"
#include "nstackx_getopt.h"
#include "nstackx_statistics.h"
#include "nstackx_common.h"
#include "nstackx_event.h"
#include "nstackx_error.h"
#include "securec.h"

#ifdef NSTACKX_DFINDER_HIDUMP

#define TAG "nStackXDFinder"
#define CRLF "\r\n"

#define DUMP_BUF_LEN (2048U)

typedef struct {
    char *buf;
    uint32_t size;
    int err;
    sem_t wait;
} DumpMsg;

static DumpMsg *CreateDumpMsg(char *buf, uint32_t size)
{
    DumpMsg *msg = (DumpMsg *)malloc(sizeof(DumpMsg));
    if (msg == NULL) {
        return NULL;
    }

    if (SemInit(&(msg->wait), 0, 0)) {
        free(msg);
        return NULL;
    }

    msg->err = NSTACKX_EOK;
    msg->buf = buf;
    msg->size = size;
    return msg;
}

static void DestroyDumpMsg(DumpMsg *msg)
{
    SemDestroy(&(msg->wait));
    free(msg);
}

static int PostDumpMsg(char *buf, uint32_t size, EventHandle handle)
{
    int ret = NSTACKX_EFAILED;
    DumpMsg *msg = CreateDumpMsg(buf, size);
    if (msg == NULL) {
        return ret;
    }

    if (PostEvent(GetEventNodeChain(), GetEpollFD(), handle, msg) != NSTACKX_EOK) {
        DestroyDumpMsg(msg);
        return ret;
    }

    SemWait(&(msg->wait));
    ret = msg->err;
    DestroyDumpMsg(msg);
    return ret;
}

typedef int (*DumpFunc)(char *buf, uint32_t size);
static int Dump(void *softObj, DFinderDumpFunc dump, DumpFunc func)
{
    char *buf = (char *)calloc(DUMP_BUF_LEN, sizeof(char));
    if (buf == NULL) {
        return NSTACKX_EFAILED;
    }

    if (func(buf, DUMP_BUF_LEN) != NSTACKX_EOK) {
        free(buf);
        return NSTACKX_EFAILED;
    }

    dump(softObj, buf, strlen(buf) + 1);
    free(buf);
    return NSTACKX_EOK;
}

static int DumpStatisticsInfo(char *buf, uint32_t size)
{
    int ret;
    uint32_t index = 0;
    const uint64_t *stat = GetStatistics();
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, CRLF"DFinder statistics:"CRLF);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_INVALID_OPT_AND_PAYLOAD: %" PRIu64 CRLF,
        stat[STATS_INVALID_OPT_AND_PAYLOAD]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_DECODE_FAILED: %" PRIu64 CRLF, stat[STATS_DECODE_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_ENCODE_FAILED: %" PRIu64 CRLF, stat[STATS_ENCODE_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_CREATE_HEADER_FAILED: %" PRIu64 CRLF,
        stat[STATS_CREATE_HEADER_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_BUILD_PKT_FAILED: %" PRIu64 CRLF, stat[STATS_BUILD_PKT_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_SOCKET_ERROR: %" PRIu64 CRLF, stat[STATS_SOCKET_ERROR]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_EPOLL_ERROR: %" PRIu64 CRLF, stat[STATS_EPOLL_ERROR]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_CREATE_SERVER_FAILED: %" PRIu64 CRLF,
        stat[STATS_CREATE_SERVER_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_CREATE_CLIENT_FAILED: %" PRIu64 CRLF,
        stat[STATS_CREATE_CLIENT_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_DROP_LOOPBACK_PKT: %" PRIu64 CRLF, stat[STATS_DROP_LOOPBACK_PKT]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_SEND_MSG_FAILED: %" PRIu64 CRLF, stat[STATS_SEND_MSG_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_SEND_REQUEST_FAILED: %" PRIu64 CRLF,
        stat[STATS_SEND_REQUEST_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_DROP_MSG_ID: %" PRIu64 CRLF, stat[STATS_DROP_MSG_ID]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_HANDLE_SERVICE_MSG_FAILED: %" PRIu64 CRLF,
        stat[STATS_HANDLE_SERVICE_MSG_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_HANDLE_DEVICE_DISCOVER_MSG_FAILED: %" PRIu64 CRLF,
        stat[STATS_HANDLE_DEVICE_DISCOVER_MSG_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_INVALID_RESPONSE_MSG: %" PRIu64 CRLF,
        stat[STATS_INVALID_RESPONSE_MSG]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_POST_SD_REQUEST_FAILED: %" PRIu64 CRLF,
        stat[STATS_POST_SD_REQUEST_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_ABORT_SD: %" PRIu64 CRLF, stat[STATS_ABORT_SD]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_START_SD_FAILED: %" PRIu64 CRLF, stat[STATS_START_SD_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_CREATE_SERVICE_MSG_FAILED: %" PRIu64 CRLF,
        stat[STATS_CREATE_SERVICE_MSG_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_SEND_SD_RESPONSE_FAILED: %" PRIu64 CRLF,
        stat[STATS_SEND_SD_RESPONSE_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_BACKUP_DEVICE_DB_FAILED: %" PRIu64 CRLF,
        stat[STATS_BACKUP_DEVICE_DB_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_UPDATE_DEVICE_DB_FAILED: %" PRIu64 CRLF,
        stat[STATS_UPDATE_DEVICE_DB_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_CREATE_CONTEX_FAILED: %" PRIu64 CRLF,
        stat[STATS_CREATE_CONTEX_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_CREATE_SESSION_FAILED: %" PRIu64 CRLF,
        stat[STATS_CREATE_SESSION_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_PREPARE_SD_MSG_FAILED: %" PRIu64 CRLF,
        stat[STATS_PREPARE_SD_MSG_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_PARSE_SD_MSG_FAILED: %" PRIu64 CRLF,
        stat[STATS_PARSE_SD_MSG_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_ALLOC_RECORD_FAILED: %" PRIu64 CRLF,
        stat[STATS_ALLOC_RECORD_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_FREE_RECORD_FAILED: %" PRIu64 CRLF,
        stat[STATS_FREE_RECORD_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "STATS_OVER_DEVICE_LIMIT: %" PRIu64 CRLF, stat[STATS_OVER_DEVICE_LIMIT]);
    return NSTACKX_EOK;
}

static void DumpStatisticsInner(void *arg)
{
    DumpMsg *msg = (DumpMsg *)arg;
    msg->err = DumpStatisticsInfo(msg->buf, msg->size);
    SemPost(&(msg->wait));
}

int DumpStatistics(char *buf, uint32_t size)
{
    return PostDumpMsg(buf, size, DumpStatisticsInner);
}

static int DumpHelp(char *buf, uint32_t size)
{
    int ret;
    int index = 0;
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, CRLF"Usage: dfinder <opt>"CRLF);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "       -h         show this help"CRLF);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "       -s         show statistics info"CRLF);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "       -m <0/1>   enable control message log"CRLF);
    return NSTACKX_EOK;
}

#define DFINDER_DUMP_STRTOL_BASE 10
static const char *g_dfinderDumpOpts = "hsm:";
int DFinderDump(const char **argv, uint32_t argc, void *softObj, DFinderDumpFunc dump)
{
    int32_t opt;
    NstackGetOptMsg optMsg;
    int32_t ret = NstackInitGetOptMsg(&optMsg);
    if (ret != NSTACKX_EOK) {
        return ret;
    }

    while ((opt = NstackGetOpt(&optMsg, argc, argv, g_dfinderDumpOpts)) != NSTACK_GETOPT_END_OF_STR) {
        switch (opt) {
            case 'h':
                ret = Dump(softObj, dump, DumpHelp);
                break;
            case 's':
                ret = Dump(softObj, dump, DumpStatistics);
                break;
            case 'm':
#ifdef DFINDER_MGT_MSG_LOG
                (void)DFinderSetMgtMsgLog((int32_t)strtol(NstackGetOptArgs(&optMsg), NULL, DFINDER_DUMP_STRTOL_BASE));
#endif
                break;
            default:
                ret = NSTACKX_EFAILED;
                DFINDER_LOGE(TAG, "Unknown option");
                break;
        }

        if (ret != NSTACKX_EOK) {
            break;
        }
    }

    return ret;
}

#endif /* NSTACKX_DFINDER_HIDUMP */
