/*
 * Copyright (c) 2015 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 p11speed.h

 This program can be used for benchmarking the performance on PKCS#11
 libraries. The default library is the libsofthsm2.so
 *****************************************************************************/

#ifndef _P11SPEED_H
#define _P11SPEED_H

#include "pkcs11.h"

// Main functions
void usage();
int showSlots();
int testSign(unsigned int slot, char* userPIN, char* mechanism, char* keysize, unsigned int threads, unsigned int iterations);

// Key generation
int generateRsa(CK_SESSION_HANDLE hSession, CK_ULONG keysize, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk);
int generateDsa(CK_SESSION_HANDLE hSession, CK_ULONG keysize, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk);
int generateEcdsa(CK_SESSION_HANDLE hSession, CK_ULONG keysize, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk);
int generateGost(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk);

// Work items for threads
void* sign(void* arg);

// Logging
void log_notice(const char* format, ...);
void log_error(const char* format, ...);
void log_fatal(const char* format, ...);

// Library
static void* moduleHandle;
extern CK_FUNCTION_LIST_PTR p11;

#define PTHREAD_THREADS_MAX 2048

struct HashAlgo
{
        enum Type
        {
                Unknown,
                SHA256,
                SHA384,
                GOST
        };
};

typedef struct {
	unsigned int id;
	unsigned int iterations;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hPrivateKey;
	CK_MECHANISM_TYPE mechanismType;
	HashAlgo::Type hashType;
} sign_arg_t;

#endif // !_P11SPEED_H
