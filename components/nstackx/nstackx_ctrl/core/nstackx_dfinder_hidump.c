/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
#include "nstackx_device.h"
#include "nstackx_event.h"
#include "nstackx_error.h"
#include "securec.h"
#include "nstackx_device_local.h"
#include "nstackx_device_remote.h"

#ifdef NSTACKX_DFINDER_HIDUMP

#define TAG "nStackXDFinder"
#define CRLF "\r\n"

#define DUMP_BUF_LEN (2048U)
#define DUMP_LARGE_BUF_LEN (409600U)
#define DFINDER_DUMP_MAX_ARGC (20U)
#define DFINDER_DUMP_STRTOL_BASE 10
static const char *g_dfinderDumpOpts = "fhlrsm:";

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
        DFINDER_LOGE(TAG, "malloc dump msg failed");
        return NULL;
    }

    if (SemInit(&(msg->wait), 0, 0)) {
        DFINDER_LOGE(TAG, "init msg wait failed");
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
        DFINDER_LOGE(TAG, "create dump msg failed");
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
static int Dump(void *softObj, uint32_t size, DFinderDumpFunc dump, DumpFunc func)
{
    if (size == 0 || size > DUMP_LARGE_BUF_LEN) {
        return NSTACKX_EFAILED;
    }

    char *buf = (char *)calloc(size, sizeof(char));
    if (buf == NULL) {
        DFINDER_LOGE(TAG, "dump malloc failed");
        return NSTACKX_EFAILED;
    }

    if (func(buf, DUMP_BUF_LEN) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "dump func exec failed");
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
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "INVALID_OPT_AND_PAYLOAD: %" PRIu64 CRLF,
        stat[STATS_INVALID_OPT_AND_PAYLOAD]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "DECODE_FAILED: %" PRIu64 CRLF, stat[STATS_DECODE_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "ENCODE_FAILED: %" PRIu64 CRLF, stat[STATS_ENCODE_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "CREATE_HEADER_FAILED: %" PRIu64 CRLF, stat[STATS_CREATE_HEADER_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "BUILD_PKT_FAILED: %" PRIu64 CRLF, stat[STATS_BUILD_PKT_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "SOCKET_ERROR: %" PRIu64 CRLF, stat[STATS_SOCKET_ERROR]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "EPOLL_ERROR: %" PRIu64 CRLF, stat[STATS_EPOLL_ERROR]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "CREATE_SERVER_FAILED: %" PRIu64 CRLF, stat[STATS_CREATE_SERVER_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "CREATE_CLIENT_FAILED: %" PRIu64 CRLF, stat[STATS_CREATE_CLIENT_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "DROP_LOOPBACK_PKT: %" PRIu64 CRLF, stat[STATS_DROP_LOOPBACK_PKT]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "SEND_MSG_FAILED: %" PRIu64 CRLF, stat[STATS_SEND_MSG_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "SEND_REQUEST_FAILED: %" PRIu64 CRLF, stat[STATS_SEND_REQUEST_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "DROP_MSG_ID: %" PRIu64 CRLF, stat[STATS_DROP_MSG_ID]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "HANDLE_SERVICE_MSG_FAILED: %" PRIu64 CRLF,
        stat[STATS_HANDLE_SERVICE_MSG_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "HANDLE_DEVICE_DISCOVER_MSG_FAILED: %" PRIu64 CRLF,
        stat[STATS_HANDLE_DEVICE_DISCOVER_MSG_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "INVALID_RESPONSE_MSG: %" PRIu64 CRLF, stat[STATS_INVALID_RESPONSE_MSG]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "POST_SD_REQUEST_FAILED: %" PRIu64 CRLF,
        stat[STATS_POST_SD_REQUEST_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "ABORT_SD: %" PRIu64 CRLF, stat[STATS_ABORT_SD]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "START_SD_FAILED: %" PRIu64 CRLF, stat[STATS_START_SD_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "CREATE_SERVICE_MSG_FAILED: %" PRIu64 CRLF,
        stat[STATS_CREATE_SERVICE_MSG_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "SEND_SD_RESPONSE_FAILED: %" PRIu64 CRLF,
        stat[STATS_SEND_SD_RESPONSE_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "BACKUP_DEVICE_DB_FAILED: %" PRIu64 CRLF,
        stat[STATS_BACKUP_DEVICE_DB_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "UPDATE_DEVICE_DB_FAILED: %" PRIu64 CRLF,
        stat[STATS_UPDATE_DEVICE_DB_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "CREATE_CONTEX_FAILED: %" PRIu64 CRLF, stat[STATS_CREATE_CONTEX_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "CREATE_SESSION_FAILED: %" PRIu64 CRLF,
        stat[STATS_CREATE_SESSION_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "PREPARE_SD_MSG_FAILED: %" PRIu64 CRLF,
        stat[STATS_PREPARE_SD_MSG_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "PARSE_SD_MSG_FAILED: %" PRIu64 CRLF, stat[STATS_PARSE_SD_MSG_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "ALLOC_RECORD_FAILED: %" PRIu64 CRLF, stat[STATS_ALLOC_RECORD_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "FREE_RECORD_FAILED: %" PRIu64 CRLF, stat[STATS_FREE_RECORD_FAILED]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "OVER_DEVICE_LIMIT: %" PRIu64 CRLF, stat[STATS_OVER_DEVICE_LIMIT]);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "COAP_RESOURCE_INIT_FAILED: %" PRIu64 CRLF,
        stat[STATS_COAP_RESOURCE_INIT_FAILED]);
    return NSTACKX_EOK;
}

static void DumpStatisticsInner(void *arg)
{
    DumpMsg *msg = (DumpMsg *)arg;
    msg->err = DumpStatisticsInfo(msg->buf, msg->size);
    SemPost(&(msg->wait));
}

static int DumpStatistics(char *buf, uint32_t size)
{
    return PostDumpMsg(buf, size, DumpStatisticsInner);
}

int DFinderDumpIface(char *buf, int size, const char *ifname, const struct in_addr *ip, uint8_t state)
{
    uint32_t index = 0;
    int ret;
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "network name:%s"CRLF, ifname);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "if state:%hhu"CRLF, state);

    struct sockaddr_in addr;
    char ipStr[NSTACKX_MAX_IP_STRING_LEN] = {0};
    (void)memset_s(&addr, sizeof(struct sockaddr_in), 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip->s_addr;
    ret = IpAddrAnonymousFormat(ipStr, NSTACKX_MAX_IP_STRING_LEN, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        return ret;
    }
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "ip: %s"CRLF, ipStr);

    return index;
}

#define DFINDER_DEVICE_ID_ANONY_LEN 6
#define DFINDER_DEVICE_ID_ANONY_REMOTE_LEN 15
int DumpDeviceInfo(const DeviceInfo *info, char *buf, int size, uint8_t remote)
{
    int ret;
    int i;
    uint32_t index = 0;
    size_t len;
    char deviceid[DFINDER_DEVICE_ID_ANONY_REMOTE_LEN + 1] = {0};
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "device name:%s"CRLF, info->deviceName);

    len = strlen(info->deviceId);
    if (len > 0) {
        size_t anonyLen = remote == NSTACKX_TRUE ? DFINDER_DEVICE_ID_ANONY_REMOTE_LEN : DFINDER_DEVICE_ID_ANONY_LEN;
        len = len > anonyLen ? anonyLen : len;
        ret = memcpy_s(deviceid, anonyLen, info->deviceId, len);
        if (ret != EOK) {
            DFINDER_LOGE(TAG, "memcpy_s failed");
            return NSTACKX_EFAILED;
        }
        DUMP_MSG_ADD_CHECK(ret, buf, index, size, "device id:%s******"CRLF, deviceid);
    }

    for (i = 0; i < NSTACKX_MAX_CAPABILITY_NUM; i++) {
        DUMP_MSG_ADD_CHECK(ret, buf, index, size, "cap %d:%u"CRLF, i, info->capabilityBitmap[i]);
    }

    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "mode:%hhu"CRLF"businessType:%hhu"CRLF, info->mode, info->businessType);
    if (remote == NSTACKX_TRUE) {
        DUMP_MSG_ADD_CHECK(ret, buf, index, size, "discoveryType:%hhu"CRLF, info->discoveryType);
    }
    return index;
}

static void DumpLocalDeviceInfoInner(void *arg)
{
    int ret;
    DumpMsg *msg = (DumpMsg *)arg;
    ret = DumpDeviceInfo(GetLocalDeviceInfo(), msg->buf, msg->size, NSTACKX_FALSE);
    if (ret < 0) {
        msg->err = ret;
    } else {
        ret = LocalIfaceDump(&msg->buf[ret], msg->size - ret);
        if (ret < 0) {
            msg->err = ret;
        } else {
            msg->err = NSTACKX_EOK;
        }
    }
    SemPost(&(msg->wait));
}

static int DumpLocalDeviceInfo(char *buf, uint32_t size)
{
    return PostDumpMsg(buf, size, DumpLocalDeviceInfoInner);
}

#ifdef DFINDER_SAVE_DEVICE_LIST
static void DumpRemoteDeviceInfoInner(void *arg)
{
    DumpMsg *msg = (DumpMsg *)arg;
    int ret = DumpRemoteDevice(msg->buf, msg->size);
    if (ret < 0) {
        msg->err = NSTACKX_EFAILED;
    } else {
        msg->err = NSTACKX_EOK;
    }
    SemPost(&(msg->wait));
}

static int DumpRemoteDeviceInfo(char *buf, uint32_t size)
{
    return PostDumpMsg(buf, size, DumpRemoteDeviceInfoInner);
}
#else
static int DumpRemoteDeviceInfo(char *buf, uint32_t size)
{
    (void)buf;
    (void)size;
    return NSTACKX_EFAILED;
}
#endif

static int DumpCapFilterInfoImp(char *buf, uint32_t size)
{
    int i;
    int ret;
    uint32_t index = 0;
    uint32_t bitmapNum;
    uint32_t *bitmap = GetFilterCapability(&bitmapNum);

    for (i = 0; i < NSTACKX_MAX_CAPABILITY_NUM; i++) {
        DUMP_MSG_ADD_CHECK(ret, buf, index, size, "filter cap %d:%u"CRLF, i, bitmap[i]);
    }

    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "filter num:%u"CRLF, bitmapNum);
    return NSTACKX_EOK;
}

static void DumpCapFilterInfoInner(void *arg)
{
    DumpMsg *msg = (DumpMsg *)arg;
    msg->err = DumpCapFilterInfoImp(msg->buf, msg->size);
    SemPost(&(msg->wait));
}

static int DumpCapFilterInfo(char *buf, uint32_t size)
{
    return PostDumpMsg(buf, size, DumpCapFilterInfoInner);
}

static int DumpHelp(char *buf, uint32_t size)
{
    int ret;
    uint32_t index = 0;
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, CRLF"Usage: dfinder <opt>"CRLF);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "       -h         show this help"CRLF);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "       -l         show local device info"CRLF);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "       -r         show remote device info"CRLF);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "       -f         show capability filter info"CRLF);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "       -s         show statistics info"CRLF);
    DUMP_MSG_ADD_CHECK(ret, buf, index, size, "       -m <0/1>   enable control message log"CRLF);
    return NSTACKX_EOK;
}

static int32_t EnableMgtMsgLog(const char *optMsg, void *softObj, DFinderDumpFunc dump)
{
    int32_t enable;

    if ((optMsg == NULL) || (strlen(optMsg) != 1) ||
        ((optMsg[0] != '0') && (optMsg[0] != '1'))) {
        const char *errMsg = "invalid parameter";
        dump(softObj, errMsg, strlen(errMsg));
        (void)Dump(softObj, DUMP_BUF_LEN, dump, DumpHelp);
        return NSTACKX_EFAILED;
    }

    enable = (int32_t)strtol(optMsg, NULL, DFINDER_DUMP_STRTOL_BASE);
#ifdef DFINDER_MGT_MSG_LOG
    (void)DFinderSetMgtMsgLog(enable);
    if (enable == 0) {
        const char *disableMsg = "disable control message log";
        dump(softObj, disableMsg, strlen(disableMsg));
    } else {
        const char *enableMsg = "enable control message log";
        dump(softObj, enableMsg, strlen(enableMsg));
    }
    return NSTACKX_EOK;
#else
    const char *unsupportMsg = "the command is unsupported";
    dump(softObj, unsupportMsg, strlen(unsupportMsg));
    return NSTACKX_EFAILED;
#endif
}

int DFinderDump(const char **argv, uint32_t argc, void *softObj, DFinderDumpFunc dump)
{
    int32_t opt;
    NstackGetOptMsg optMsg;
    int32_t ret = NstackInitGetOptMsg(&optMsg);
    if (ret != NSTACKX_EOK) {
        return ret;
    }

    if (argc == 1) {
        (void)Dump(softObj, DUMP_BUF_LEN, dump, DumpHelp);
        return NSTACKX_EOK;
    }

    ret = NSTACKX_EFAILED;
    while ((opt = NstackGetOpt(&optMsg, argc, argv, g_dfinderDumpOpts)) != NSTACK_GETOPT_END_OF_STR) {
        switch (opt) {
            case 'h':
                ret = Dump(softObj, DUMP_BUF_LEN, dump, DumpHelp);
                break;
            case 's':
                ret = Dump(softObj, DUMP_BUF_LEN, dump, DumpStatistics);
                break;
            case 'l':
                ret = Dump(softObj, DUMP_BUF_LEN, dump, DumpLocalDeviceInfo);
                break;
            case 'r':
                ret = Dump(softObj, DUMP_LARGE_BUF_LEN, dump, DumpRemoteDeviceInfo);
                break;
            case 'f':
                ret = Dump(softObj, DUMP_BUF_LEN, dump, DumpCapFilterInfo);
                break;
            case 'm':
                ret = EnableMgtMsgLog(NstackGetOptArgs(&optMsg), softObj, dump);
                break;
            default:
                ret = NSTACKX_EFAILED;
                (void)Dump(softObj, DUMP_BUF_LEN, dump, DumpHelp);
                DFINDER_LOGE(TAG, "unknown option");
                break;
        }

        if (ret != NSTACKX_EOK) {
            break;
        }
    }

    return ret;
}

#endif /* NSTACKX_DFINDER_HIDUMP */
