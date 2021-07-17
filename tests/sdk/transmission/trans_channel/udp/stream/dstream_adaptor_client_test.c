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

#include "client_trans_udp_stream_interface.h"
#include "session.h"

#define CHANNELID 1
#define CHANNELID2 2
#define PKGNAME   "test"
#define TWO_CLIENT_ARGC   3
#define FIRST_ARGV   1
#define SECOND_ARGV   2
#define SHORT_SLEEP   3
#define LONG_SLEEP    30
#define LOOP_ROUND    10


void SetStatus(int channelId, int status)
{
    printf("[client]:channelID:%d, status:%d\n", channelId, status);
}

void OnStreamReceived(int channelId, const StreamData *data, const StreamData *ext, const FrameInfo *param)
{
    printf("[client]:OnStreamReceived, len:%d, extLen:%d", data->bufLen, ext->bufLen);
    printf("[client]:channelID:%d, streamBuf:%.*s\n", channelId, data->bufLen, data->buf);
}

static IStreamListener g_callback = {
    .OnStatusChange = SetStatus,
    .OnStreamReceived = OnStreamReceived,
};

int main(int argc, char *argv[])
{
    if (argc != TWO_CLIENT_ARGC) {
        printf("[client]:Please input server sorcket to connect\n");
        return 0;
    }
    int port = atoi(argv[FIRST_ARGV]);
    int port2 = atoi(argv[SECOND_ARGV]);
    int ret;

    VtpStreamOpenParam p1 = {
        PKGNAME,
        "127.0.0.1",
        "127.0.0.1",
        port,
        RAW_STREAM,
        "abcdefghabcdefghabcdefghabcdefgh",
    };

    VtpStreamOpenParam p2 = {
        PKGNAME,
        "127.0.0.1",
        "127.0.0.1",
        port2,
        RAW_STREAM,
        "abcdefghabcdefghabcdefghabcdefgh",
    };

    ret = StartVtpStreamChannelClient(CHANNELID, &p1, &g_callback);
    printf("[client]:StartChannelClient ret:%d\n", ret);

    ret = StartVtpStreamChannelClient(CHANNELID2, &p2, &g_callback);
    printf("[client]:StartChannelClient ret:%d\n", ret);

    sleep(SHORT_SLEEP);

    StreamData tmpData = {
        "diudiudiu\0",
        10,
    };

    StreamData tmpData2 = {
        "oohoohooh\0",
        10,
    };
    FrameInfo tmpf = {};

    for (int i  = 0; i < LOOP_ROUND; i++) {
        ret = SendVtpStream(CHANNELID, &tmpData, NULL, &tmpf);
        printf("[client]:DstreamSendStream1 ret:%d\n", ret);
        ret = SendVtpStream(CHANNELID2, &tmpData2, NULL, &tmpf);
        printf("[client]:DstreamSendStream2 ret:%d\n", ret);
        sleep(LONG_SLEEP);
    }

    CloseVtpStreamChannel(CHANNELID, PKGNAME);
    CloseVtpStreamChannel(CHANNELID2, PKGNAME);
    sleep(LONG_SLEEP);

    return 0;
}
