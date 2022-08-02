/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: the types of dfinder hievent.
 * Author: NA
 * Create: 2022-07-21
 */

#ifndef NSTACKX_DFINDER_HIEVENT_H
#define NSTACKX_DFINDER_HIEVENT_H
#include "nstackx.h"

int SetEventFunc(void *softobj, DFinderEventFunc func);
void NotifyStatisticsEvent(void);

#endif