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
#include <stdio.h>
#include <string.h>
#include "softbus_hidumper.h"

#define CMD_REGISTED_SESSION_LIST "registed_sessionlist"
#define CMD_CONCURRENT_SESSION_LIST "concurrent_sessionlist"

typedef void(*ShowDumpInfosFunc)(int fd);

typedef struct{
	const char* cmd;
	ShowDumpInfosFunc showDumpInfosFunc;
}TransHiDumperCmd;

typedef enum {
	TRANS_HIDUMPER_CMD_REGISTED_SESSION_LIST = 0,
    TRANS_HIDUMPER_CMD_CONCURRENT_SESSION_LIST,

    TRANS_HIDUMPER_CMD_BUTT
}TransHiDumperCmdType;

void ShowTransDumpHelperInfo(int fd)
{
    dprintf(fd, "Usage: -l [%s] [%s]\n", CMD_REGISTED_SESSION_LIST, CMD_CONCURRENT_SESSION_LIST);
    dprintf(fd, "  %20s    List all the registed sessionlist\n", CMD_REGISTED_SESSION_LIST);
    dprintf(fd, "  %20s    List all the running sessionlist\n", CMD_CONCURRENT_SESSION_LIST);
}

void ShowTransRegistedSessionList(int fd)
{

}

void ShowTransRunningSessionList(int fd)
{

}

TransHiDumperCmd g_transHiDumperCmdList[TRANS_HIDUMPER_CMD_BUTT] = {
	{CMD_REGISTED_SESSION_LIST, ShowTransRegistedSessionList},
	{CMD_CONCURRENT_SESSION_LIST, ShowTransRunningSessionList}
};

void SoftBusTransDumpHander(int fd, int argc, const char **argv)
{
	if ((argc != 2) || (strcmp(argv[0], "-l") != 0)) {
		ShowTransDumpHelperInfo(fd);
		return;
	}

	for (unsigned int i = 0; i < TRANS_HIDUMPER_CMD_BUTT; i++) {
		if (strcmp(argv[1], g_transHiDumperCmdList[i].cmd) == 0) {
			g_transHiDumperCmdList[i].showDumpInfosFunc(fd);
			return;
		}
	}

	ShowTransDumpHelperInfo(fd);
}