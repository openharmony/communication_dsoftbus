/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * miscservices under the License is miscservices on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "distributed_stream_test.h"

#include "gtest/gtest.h"
#include <cstring>
#include <ctime>
#include <iostream>
#include <semaphore.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include "securec.h"
#include "softbus_bus_center.h"
#include "session.h"
#include "softbus_common.h"
#include "softbus_access_token_test.h"
#include "distributed_agent.h"

using namespace std;
using namespace testing;
using namespace testing::ext;
using namespace OHOS::DistributeSystemTest;

static bool g_isTerminal = false;
namespace OHOS {

void SetNumebrInStreamData(char *streamData, int i)
{
    string strI = std::to_string(i);
    char len = strI.length();
    streamData[0] = len;
    (void)memcpy_s(streamData + 1, len, strI.c_str(), len);
}

int GetNumebrInStreamData(const char *streamData)
{
    char len = streamData[0];
    string str(streamData + 1, len);

    return std::stoi(str);
}

class DistributeStreamTestAgent : public DistributedAgent {
public:
    virtual bool SetUp();
    virtual bool TearDown();

    static int OnsessionOpened(int sessionId, int result);
    static int OnCtrlsessionOpened(int sessionId, int result);
    static void OnSessionClosed(int sessionId);
    static void OnStreamReceived(int sessionId, const StreamData *data,
        const StreamData *ext, const StreamFrameInfo *param);
    static void OnBytesReceived(int sessionId, const void *data, unsigned int dataLen);

    virtual int OnProcessMsg(const string &msg, int len, string &strReturnValue, int returnValueLen);
    int CreateTestSessionServer(string &strReturnValue);
    int RemoverTestSessionServer(string &strReturnValue);
    int TerminalServer(string &strReturnValue);

    static int contrlSessionId_;
    static char sendBytes[BYTES_SIZE];

    using MsgFunc = int (DistributeStreamTestAgent::*)(string &);
    static map<string, MsgFunc> msgFunMap;
};

int DistributeStreamTestAgent::contrlSessionId_ = 0;
char DistributeStreamTestAgent::sendBytes[BYTES_SIZE];
map<string, DistributeStreamTestAgent::MsgFunc> DistributeStreamTestAgent::msgFunMap;

int DistributeStreamTestAgent::OnsessionOpened(int sessionId, int result)
{
    EXPECT_EQ(result, 0);

    return 0;
}

int DistributeStreamTestAgent::OnCtrlsessionOpened(int sessionId, int result)
{
    EXPECT_EQ(result, 0);
    if (result == 0) {
        contrlSessionId_ = sessionId;
    }

    return 0;
}

void DistributeStreamTestAgent::OnSessionClosed(int sessionId)
{
}

void DistributeStreamTestAgent::OnStreamReceived(int sessionId, const StreamData *data,
    const StreamData *ext, const StreamFrameInfo *param)
{
    int i = GetNumebrInStreamData((const char*)data->buf);
    if (i < 0) {
        return;
    }
    SetNumebrInStreamData(sendBytes, i);
    int ret = SendBytes(contrlSessionId_, sendBytes, BYTES_SIZE);
    EXPECT_EQ(ret, 0);
}

void DistributeStreamTestAgent::OnBytesReceived(int sessionId, const void *data, unsigned int dataLen)
{
}

static ISessionListener g_listener = {
    .OnSessionOpened = DistributeStreamTestAgent::OnsessionOpened,
    .OnSessionClosed = DistributeStreamTestAgent::OnSessionClosed,
    .OnBytesReceived = DistributeStreamTestAgent::OnBytesReceived,
    .OnStreamReceived = DistributeStreamTestAgent::OnStreamReceived
};

static ISessionListener g_ctrllistener = {
    .OnSessionOpened = DistributeStreamTestAgent::OnCtrlsessionOpened,
    .OnSessionClosed = DistributeStreamTestAgent::OnSessionClosed,
    .OnBytesReceived = DistributeStreamTestAgent::OnBytesReceived,
    .OnStreamReceived = DistributeStreamTestAgent::OnStreamReceived
};

bool DistributeStreamTestAgent::SetUp()
{
    msgFunMap["createSessionServer"] = &DistributeStreamTestAgent::CreateTestSessionServer;
    msgFunMap["TerminalServer"] = &DistributeStreamTestAgent::TerminalServer;
    msgFunMap["removeSessionServer"] = &DistributeStreamTestAgent::RemoverTestSessionServer;

    SetAceessTokenPermission("distributed_stream_test");

    cout << "agent start" <<endl;
    return true;
}

bool DistributeStreamTestAgent::TearDown()
{
    return true;
}

int DistributeStreamTestAgent::CreateTestSessionServer(string &strReturnValue)
{
    int ret = CreateSessionServer(TEST_PKG_NAME.c_str(), STREAM_SESSION_NAME.c_str(), &g_listener);
    EXPECT_EQ(ret, 0);
    cout << "pkgName : " << TEST_PKG_NAME << ", sessionName : " << STREAM_SESSION_NAME << endl;

    ret = CreateSessionServer(TEST_PKG_NAME.c_str(), CONTRL_SESSION_NAME.c_str(), &g_ctrllistener);
    EXPECT_EQ(ret, 0);
    cout << "pkgName : " << TEST_PKG_NAME << ", sessionName : " << CONTRL_SESSION_NAME << endl;

    strReturnValue = "ok";
    return strReturnValue.length();
}

int DistributeStreamTestAgent::RemoverTestSessionServer(string &strReturnValue)
{
    int ret = RemoveSessionServer(TEST_PKG_NAME.c_str(), STREAM_SESSION_NAME.c_str());
    EXPECT_EQ(ret, 0);

    ret = RemoveSessionServer(TEST_PKG_NAME.c_str(), CONTRL_SESSION_NAME.c_str());
    EXPECT_EQ(ret, 0);

    strReturnValue = "ok";
    return strReturnValue.length();
}

int DistributeStreamTestAgent::TerminalServer(string &strReturnValue)
{
    g_isTerminal = true;
    strReturnValue = "ok";
    return strReturnValue.length();
}

int DistributeStreamTestAgent::OnProcessMsg(const string &msg, int len, string &strReturnValue, int returnValueLen)
{
    cout << "receive message: " << msg <<endl;
    map<string, MsgFunc>::iterator it = msgFunMap.find(msg);
    if (it != msgFunMap.end()) {
        MsgFunc msgFunc = msgFunMap[msg];
        return (this->*msgFunc)(strReturnValue);
    }

    return -1;
}
}

int main()
{
    OHOS::DistributeStreamTestAgent obj;
    if (obj.SetUp()) {
        obj.Start("agent.desc");
        obj.Join();
    } else {
        cout << "init environment failed" << endl;
    }

    while (!g_isTerminal) {
        sleep(1);
    }

    if (obj.TearDown()) {
        return 0;
    } else {
        cout << "clear environment failed" << endl;
        return -1;
    }
}