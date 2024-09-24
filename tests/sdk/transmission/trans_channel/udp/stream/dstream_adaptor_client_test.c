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

#include <stdio.h>
#include <unistd.h>

#include "client_trans_udp_stream_interface.h"
#include "securec.h"
#include "session.h"
#include "softbus_error_code.h"

#define CHANNELID 1
#define CHANNELID2 2
#define PKGNAME   "test"
#define TWO_CLIENT_ARGC   3
#define FIRST_ARGV   1
#define SECOND_ARGV   2
#define SHORT_SLEEP   3
#define LONG_SLEEP    30
#define LOOP_ROUND    10
#define SESSION_KEY_LENGTH   32
#define STREAM_DATA_LENGTH   10

void SetStatus(int32_t channelId, int32_t status)
{
    printf("[client]:channelID:%d, status:%d\n", channelId, status);
}

void OnStreamReceived(int32_t channelId, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    printf("[client]:OnStreamReceived, len:%d, extLen:%d", data->bufLen, ext->bufLen);
    printf("[client]:channelID:%d, streamBuf:%.*s\n", channelId, data->bufLen, data->buf);
}

static IStreamListener g_callback = {
    .OnStatusChange = SetStatus,
    .OnStreamReceived = OnStreamReceived,
};

int32_t ConstructVtpStreamOpenParam(VtpStreamOpenParam *p1, VtpStreamOpenParam *p2, char *argv[])
{
    int32_t port = 0;
    if (sscanf_s(argv[FIRST_ARGV], "%d", &port) <= 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t port2 = 0;
    if (sscanf_s(argv[SECOND_ARGV], "%d", &port2) <= 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    p1->pkgName = PKGNAME;
    p1->myIp = "127.0.0.1";
    p1->peerIp = "127.0.0.1";
    p1->peerPort = port;
    p1->type = RAW_STREAM;
    p1->sessionKey = (uint8_t*)"abcdef@ghabcdefghabcdefghfgdabc";
    p1->keyLen = SESSION_KEY_LENGTH;

    p2->pkgName = PKGNAME;
    p2->myIp = "127.0.0.1";
    p2->peerIp = "127.0.0.1";
    p2->peerPort = port2;
    p2->type = RAW_STREAM;
    p2->sessionKey = (uint8_t*)"abcdef\0ghabcdefghabcdefghfgdabc";
    p2->keyLen = SESSION_KEY_LENGTH;

    return SOFTBUS_OK;
}

int32_t SendVtpStreamTest(VtpStreamOpenParam *p1, VtpStreamOpenParam *p2, const IStreamListener *callback)
{
    if (p1 == NULL || p2 == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = StartVtpStreamChannelClient(CHANNELID, p1, callback);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    printf("[client]:StartChannelClient ret:%d\n", ret);

    ret = StartVtpStreamChannelClient(CHANNELID2, p2, callback);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    printf("[client]:StartChannelClient ret:%d\n", ret);

    sleep(SHORT_SLEEP);

    StreamData tmpData = {
        "diudiudiu\0",
        STREAM_DATA_LENGTH,
    };

    StreamData tmpData2 = {
        "oohoohooh\0",
        STREAM_DATA_LENGTH,
    };
    StreamFrameInfo tmpf = {};

    for (int32_t i  = 0; i < LOOP_ROUND; i++) {
        ret = SendVtpStream(CHANNELID, &tmpData, NULL, &tmpf);
        printf("[client]:DstreamSendStream1 ret:%d\n", ret);
        ret = SendVtpStream(CHANNELID2, &tmpData2, NULL, &tmpf);
        printf("[client]:DstreamSendStream2 ret:%d\n", ret);
        sleep(LONG_SLEEP);
    }

    CloseVtpStreamChannel(CHANNELID, PKGNAME);
    CloseVtpStreamChannel(CHANNELID2, PKGNAME);
    sleep(LONG_SLEEP);

    return SOFTBUS_OK;
}

int32_t main(int32_t argc, char *argv[])
{
    if (argc != TWO_CLIENT_ARGC) {
        printf("[client]:Please input server sorcket to connect\n");
        return SOFTBUS_INVALID_PARAM;
    }
    VtpStreamOpenParam p1;
    VtpStreamOpenParam p2;
    int32_t ret = ConstructVtpStreamOpenParam(&p1, &p2, argv);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    ret = SendVtpStreamTest(&p1, &p2, &g_callback);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    return SOFTBUS_OK;
}
