/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_CONFIG_H
#define NSTACKX_CONFIG_H

#ifdef NSTACKX_WITH_LITEOS

/**
 * Enable(1) or Disable(0) fillp support in nStackx
 */
#ifndef NSTACKX_SUPPORT_FILLP
#define NSTACKX_SUPPORT_FILLP 0
#endif

/**
 * Enable(1) or Disable(0) encrypt support in nStackx
 */
#ifndef NSTACKX_SUPPORT_ENCRYPT
#define NSTACKX_SUPPORT_ENCRYPT 0
#endif

#endif /* NSTACKX_WITH_LITEOS */

#ifdef NSTACKX_WITH_HMOS_LINUX

#ifndef NSTACKX_SUPPORT_ENCRYPT
#define NSTACKX_SUPPORT_ENCRYPT 0
#endif

#endif /* NSTACKX_WITH_HMOS_LINUX */

#ifndef NSTACKX_SUPPORT_FILLP
#define NSTACKX_SUPPORT_FILLP 1
#endif

#ifndef NSTACKX_SUPPORT_ENCRYPT
#define NSTACKX_SUPPORT_ENCRYPT 1
#endif

#endif /* NSTACKX_CONFIG_H */
