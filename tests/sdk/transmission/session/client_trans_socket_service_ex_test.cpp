/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>

#include "client_trans_socket_service.c"
#include "softbus_error_code.h"
#include "trans_type.h"
#include "trans_common_mock.h"
#include "trans_manager_mock.h"
#include "trans_service_mock.h"

using namespace std;
using namespace testing;
using namespace testing::ext;
using testing::NiceMock;

#define STRING_INFO_SIZE 20
#define DEFAULT_MAX_WAIT_TIMEOUT 30000

namespace OHOS {

class ClientTransSocketExTest : public testing::Test { };

static ClientEnhanceFuncList g_pfnClientEnhanceFuncList;

typedef enum {
    EXCUTE_IN_FIRST_TIME = 1,
    EXCUTE_IN_SECOND_TIME,
    EXCUTE_IN_THIRD_TIME,
    EXCUTE_IN_FOURTH_TIME,
    EXCUTE_IN_FIFTH_TIME,
    EXCUTE_IN_SIXTH_TIME
} ExcuteTimes;

int32_t MySetExtSocketOptFunc(int32_t socket, OptLevel level, OptType optType, void *optValue, uint32_t optValueSize)
{
    (void)socket;
    (void)level;
    (void)optType;
    (void)optValue;
    (void)optValueSize;
    return SOFTBUS_OK;
}

/*
 * @tc.name: ClientCheckFuncPointerTest001
 * @tc.desc: ClientCheckFuncPointer with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransSocketExTest, ClientCheckFuncPointerTest001, TestSize.Level1)
{
    int32_t ret = ClientCheckFuncPointer(nullptr);
    EXPECT_EQ(ret, SOFTBUS_FUNC_NOT_REGISTER);

    ret = ClientCheckFuncPointer(reinterpret_cast<void *>(MySetExtSocketOptFunc));
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SetExtSocketOptPackedTest001
 * @tc.desc: SetExtSocketOptPacked with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransSocketExTest, SetExtSocketOptPackedTest001, TestSize.Level1)
{
    NiceMock<TransCommInterfaceMock> transCommInterfaceMock;
    g_pfnClientEnhanceFuncList.setExtSocketOpt = nullptr;
    EXPECT_CALL(transCommInterfaceMock, ClientEnhanceFuncListGet).WillOnce(Return(&g_pfnClientEnhanceFuncList))
        .WillRepeatedly([]() -> ClientEnhanceFuncList* {
        g_pfnClientEnhanceFuncList.setExtSocketOpt = MySetExtSocketOptFunc;
        return &g_pfnClientEnhanceFuncList;
    });
    int32_t ret = SetExtSocketOptPacked(0, OPT_LEVEL_SOFTBUS, OPT_TYPE_BEGIN, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);

    ret = SetExtSocketOptPacked(0, OPT_LEVEL_SOFTBUS, OPT_TYPE_BEGIN, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

int32_t MyGetExtSocketOptFunc(int32_t socket, OptLevel level, OptType optType, void *optValue, int32_t *optValueSize)
{
    (void)socket;
    (void)level;
    (void)optType;
    (void)optValue;
    (void)optValueSize;
    return SOFTBUS_OK;
}

/*
 * @tc.name: GetExtSocketOptPackedTest001
 * @tc.desc: GetExtSocketOptPacked with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransSocketExTest, GetExtSocketOptPackedTest001, TestSize.Level1)
{
    NiceMock<TransCommInterfaceMock> transCommInterfaceMock;
    g_pfnClientEnhanceFuncList.getExtSocketOpt = nullptr;
    EXPECT_CALL(transCommInterfaceMock, ClientEnhanceFuncListGet).WillOnce(Return(&g_pfnClientEnhanceFuncList))
        .WillRepeatedly([]() -> ClientEnhanceFuncList* {
        g_pfnClientEnhanceFuncList.getExtSocketOpt = MyGetExtSocketOptFunc;
        return &g_pfnClientEnhanceFuncList;
    });
    int32_t ret = GetExtSocketOptPacked(0, OPT_LEVEL_SOFTBUS, OPT_TYPE_BEGIN, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);

    ret = GetExtSocketOptPacked(0, OPT_LEVEL_SOFTBUS, OPT_TYPE_BEGIN, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: WriteAcessInfoToBufTest001
 * @tc.desc: WriteAcessInfoToBuf with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransSocketExTest, WriteAcessInfoToBufTest001, TestSize.Level1)
{
    NiceMock<TransCommInterfaceMock> transCommInterfaceMock;
    EXPECT_CALL(transCommInterfaceMock, WriteInt32ToBuf).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transCommInterfaceMock, WriteUint64ToBuf).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transCommInterfaceMock, WriteStringToBuf).WillRepeatedly(
        [](uint8_t *buf, uint32_t bufLen, int32_t *offSet, char *data, uint32_t dataLen) -> int32_t {
        (void)buf;
        (void)bufLen;
        (void)offSet;
        (void)data;
        (void)dataLen;
        static int32_t times = 0;
        times++;
        if (times == EXCUTE_IN_FIRST_TIME) {
            return SOFTBUS_INVALID_PARAM;
        }
        if (times == EXCUTE_IN_SECOND_TIME) {
            return SOFTBUS_OK;
        }
        if (times == EXCUTE_IN_THIRD_TIME) {
            return SOFTBUS_INVALID_PARAM;
        }
        return SOFTBUS_OK;
    });

    SocketAccessInfo accessInfo = {
        .localTokenId = 0,
        .extraAccessInfo = reinterpret_cast<char *>(SoftBusCalloc(STRING_INFO_SIZE)),
    };
    char *sessionName = reinterpret_cast<char *>(SoftBusCalloc(STRING_INFO_SIZE));
    strcpy_s(sessionName, STRING_INFO_SIZE, "sessionName");
    strcpy_s(accessInfo.extraAccessInfo, STRING_INFO_SIZE, "extraAccessInfo");

    int32_t ret = WriteAcessInfoToBuf(nullptr, 0, sessionName, &accessInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = WriteAcessInfoToBuf(nullptr, 0, sessionName, &accessInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = WriteAcessInfoToBuf(nullptr, 0, sessionName, &accessInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = WriteAcessInfoToBuf(nullptr, 0, sessionName, &accessInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = WriteAcessInfoToBuf(nullptr, 0, sessionName, &accessInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(sessionName);
    SoftBusFree(accessInfo.extraAccessInfo);
}

/*
 * @tc.name: SetAccessInfoTest001
 * @tc.desc: SetAccessInfo with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransSocketExTest, SetAccessInfoTest001, TestSize.Level1)
{
    NiceMock<TransMgrInterfaceMock> transMgrInterfaceMock;
    EXPECT_CALL(transMgrInterfaceMock, ClientGetSessionNameBySessionId).WillRepeatedly(Return(SOFTBUS_OK));

    SocketAccessInfo accessInfo = {
        .extraAccessInfo = nullptr,
        .userId = -1,
    };
    int32_t ret = SetAccessInfo(0, accessInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    accessInfo.userId = 0;
    ret = SetAccessInfo(0, accessInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    accessInfo.userId = -1;

    accessInfo.extraAccessInfo = reinterpret_cast<char *>(SoftBusCalloc(STRING_INFO_SIZE));
    strcpy_s(accessInfo.extraAccessInfo, STRING_INFO_SIZE, "extraAccessInfo");
    ret = SetAccessInfo(0, accessInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    accessInfo.userId = 0;

    NiceMock<TransCommInterfaceMock> transCommInterfaceMock;
    EXPECT_CALL(transCommInterfaceMock, WriteInt32ToBuf).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transCommInterfaceMock, WriteUint64ToBuf).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transCommInterfaceMock, WriteStringToBuf).WillRepeatedly(Return(SOFTBUS_OK));
    ret = SetAccessInfo(0, accessInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(transCommInterfaceMock, ServerIpcProcessInnerEvent).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = SetAccessInfo(0, accessInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = SetAccessInfo(0, accessInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(accessInfo.extraAccessInfo);
}

/*
 * @tc.name: BindAsyncTest001
 * @tc.desc: BindAsync with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransSocketExTest, BindAsyncTest001, TestSize.Level1)
{
    NiceMock<TransMgrInterfaceMock> transMgrInterfaceMock;
    EXPECT_CALL(transMgrInterfaceMock, IsSessionExceedLimit).WillOnce(Return(true))
        .WillRepeatedly(Return(false));

    QosTV qos[1];
    ISocketListener listener;
    int32_t ret = BindAsync(0, qos, 0, &listener);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_CNT_EXCEEDS_LIMIT);

    EXPECT_CALL(transMgrInterfaceMock, GetQosValue).WillRepeatedly(
        [](const QosTV *qos, uint32_t qosCount, QosType type, int32_t *value, int32_t defVal) -> int32_t {
        (void)qos;
        (void)qosCount;
        (void)type;
        (void)defVal;
        *value = DEFAULT_MAX_WAIT_TIMEOUT;
        return SOFTBUS_OK;
    });
    EXPECT_CALL(transMgrInterfaceMock, ClientHandleBindWaitTimer).WillOnce(Return(SOFTBUS_ALREADY_TRIGGERED))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM)).WillRepeatedly(Return(SOFTBUS_OK));
    ret = BindAsync(0, qos, 0, &listener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = BindAsync(0, qos, 0, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(transMgrInterfaceMock, SetSessionStateBySessionId).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransServiceInterfaceMock> transServiceInterfaceMock;
    EXPECT_CALL(transServiceInterfaceMock, ClientBind).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = BindAsync(0, qos, 0, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = BindAsync(0, qos, 0, &listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS
