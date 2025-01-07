/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "clienttransproxymanager_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <securec.h>
#include <unistd.h>

#include "client_trans_proxy_manager.h"
#include "client_trans_pending.h"
#include "client_trans_proxy_file_common.h"
#include "client_trans_proxy_file_manager.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "client_trans_tcp_direct_message.h"
#include "fuzz_data_generator.h"
#include "softbus_adapter_errcode.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_app_info.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"
#include "trans_server_proxy.h"

namespace OHOS {
void ClientTransProxyManagerTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    DataGenerator::Write(data, size);
    char *sessionName = nullptr;
    ChannelInfo channel = {0};
    int32_t channelId = 0;
    const void *clientData = nullptr;
    uint32_t len = 0;
    int32_t pktType = 0;
    int32_t type = 0;
    const char **sFileList = nullptr;
    const char **dFileList = nullptr;
    uint32_t fileCnt = 0;
    int32_t sessionId = 0;
    const char *charData = nullptr;
    GenerateInt32(channelId);
    GenerateUint32(len);
    GenerateInt32(pktType);
    GenerateInt32(type);
    GenerateUint32(fileCnt);
    GenerateInt32(sessionId);

    ClientTransProxyOnChannelOpened(sessionName, &channel);

    ClientTransProxyOnDataReceived(channelId, clientData, len, (SessionPktType)pktType);

    ClientTransProxyCloseChannel(channelId);

    TransProxyChannelSendBytes(channelId, clientData, len, false);

    TransProxyChannelSendMessage(channelId, clientData, len);

    TransProxyChannelSendFile(channelId, sFileList, dFileList, fileCnt);

    ProcessFileFrameData(sessionId, channelId, charData, len, type);
    DataGenerator::Clear();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ClientTransProxyManagerTest(data, size);
    return 0;
}
