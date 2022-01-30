#ifndef SOFTBUS_TEST_ENTERY_H
#define SOFTBUS_TEST_ENTERY_H

#include <string>
#include <unordered_map>

const std::string TEST_PKG_NAME = "com.huawei.plrdtest.dsoftbus";
const std::string STREAM_SESSION_NAME = "com.huawei.plrdtest.dsoftbus.JtSendRawStream_0";
const std::string STREAM_SESSION_NAME_2 = "com.huawei.plrdtest.dsoftbus.JtSendRawStreamAct_0";
const std::string BYTES_SESSION_NAME = "com.huawei.plrdtest.dsoftbus.JtSendBytes";
const std::string CONTRL_SESSION_NAME = "com.huawei.plrdtest.dsoftbus.TestContrl";
const std::string TERMINAL_CTRL_MESSAGE = "stop this testcase";
const int OPEN_SESSION_DELAY = 2000;

struct SoftbusTestEntry {
    bool isServer_;
    bool isTestWithPhone_;
    int aliveTime_;
    int transNums_;
    int pressureNums_;
    int transLinkType_;
};

const SoftbusTestEntry *GetTestEntry(void);

#endif