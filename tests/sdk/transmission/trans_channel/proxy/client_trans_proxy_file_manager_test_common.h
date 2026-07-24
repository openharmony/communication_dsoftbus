/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef CLIENT_TRANS_PROXY_FILE_MANAGER_TEST_COMMON_H
#define CLIENT_TRANS_PROXY_FILE_MANAGER_TEST_COMMON_H

#include "securec.h"
#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "client_trans_file_listener.h"
#include "g_enhance_sdk_func.h"
#include "session.h"
#include "softbus_access_token_test.h"
#include "softbus_app_info.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_server_frame.h"
#include "softbus_trans_def.h"

#define TEST_FILE_LENGTH        10
#define TEST_FILE_CNT           2
#define TEST_CHANNEL_ID         2
#define TEST_SESSION_ID         1
#define TEST_SEQ                1020
#define TEST_SEQ_SECOND         2
#define TEST_HEADER_LENGTH      24
#define TEST_HEADER_LENGTH_MIN  13
#define TEST_FILE_PATH          "/data/file.txt"
#define TEST_DATA_LENGTH        6
#define TEST_FILE_SIZE          1000
#define TEST_PATH_SIZE          50
#define TEST_FILE_TEST_TXT_FILE 16
#define TEST_FILE_MAGIC_OFFSET  0
#define TEST_FRAME_NUMBER       2
#define TEST_FRAME_DATA_LENGTH  10
#define TEST_FILEPATH_LENGTH    4
#define TEST_SEQ8               8
#define TEST_SEQ16              16
#define TEST_SEQ32              32
#define TEST_SEQ126             126
#define TEST_SEQ128             128
#define TEST_OS_TYPE            10
#define TEST_PACKET_SIZE        1024
#define TEST_INVALID_LEN        (-1)

namespace OHOS {
extern const char *g_pkgName;
extern const char *g_sessionName;
extern const char *g_peerNetworkId;
extern const char *g_groupId;
extern FILE *g_fileTest;
extern FILE *g_fileSs;
extern int32_t g_fd;
extern char g_writeData[128];
extern const char *g_rootDir;
extern const char *g_destFile;
extern char g_recvFile[];
extern const char *g_sessionKey;
extern SessionAttribute g_attr;
extern SessionParam g_param;
extern const char *g_testProxyFileList[];
extern const char *g_fileList[];
extern const IFileSendListener g_listener;
extern const IFileReceiveListener g_fileRecvListener;

class ClientTransProxyFileManagerTest : public testing::Test {
public:
    ClientTransProxyFileManagerTest() { }
    ~ClientTransProxyFileManagerTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};
} // namespace OHOS

#endif // CLIENT_TRANS_PROXY_FILE_MANAGER_TEST_COMMON_H
