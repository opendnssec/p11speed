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
 p11speed.cpp

 This program can be used for benchmarking the performance on PKCS#11
 libraries. The default library is the libsofthsm2.so
 *****************************************************************************/

#include <config.h>
#include "p11speed.h"
#include "getpw.h"
#include "library.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#endif
#include <iostream>
#include <fstream>
#include <pthread.h>

// Display the usage
void usage()
{
	printf("Speed test for PKCS#11\n");
	printf("Usage: p11speed [ACTION] [OPTIONS]\n");
	printf("Action:\n");
	printf("  -h                 Shows this help screen.\n");
	printf("  --help             Shows this help screen.\n");
	printf("  --sign             Performe signature speed test.\n");
	printf("                     Use with --slot, --pin, --mechanism,\n");
	printf("                     --keysize, --threads and --iterations\n");
	printf("  --show-slots       Display all the available slots.\n");
	printf("  -v                 Show version info.\n");
	printf("  --version          Show version info.\n");
	printf("Options:\n");
	printf("  --iterations <nr>  The number of iterations per thread.\n");
	printf("  --keysize <bits>   Select key size in bits.\n");
	printf("  --module <path>    Use another PKCS#11 library than SoftHSM.\n");
	printf("  --mechanism <mech> Use this mechanism for the speed test.\n");
	printf("                     Sign: RSA_PKCS  [1024-4096]\n");
	printf("                           DSA       [1024-4096]\n");
	printf("                           ECDSA     [256,384]\n");
	printf("                           GOSTR3410\n");
	printf("  --module <path>    Use another PKCS#11 library than SoftHSM.\n");
	printf("  --pin <PIN>        The PIN for the normal user.\n");
	printf("  --slot <number>    The slot where the token is located.\n");
	printf("  --threads <number> The number of threads.\n");
}

// Enumeration of the long options
enum {
	OPT_HELP = 0x100,
	OPT_ITERATIONS,
	OPT_KEYSIZE,
	OPT_MECHANISM,
	OPT_MODULE,
	OPT_PIN,
	OPT_SHOW_SLOTS,
	OPT_SIGN,
	OPT_SLOT,
	OPT_THREADS,
	OPT_VERSION
};

// Text representation of the long options
static const struct option long_options[] = {
	{ "help",            0, NULL, OPT_HELP },
	{ "iterations",      1, NULL, OPT_ITERATIONS },
	{ "keysize",         1, NULL, OPT_KEYSIZE },
	{ "mechanism",       1, NULL, OPT_MECHANISM },
	{ "module",          1, NULL, OPT_MODULE },
	{ "pin",             1, NULL, OPT_PIN },
	{ "show-slots",      0, NULL, OPT_SHOW_SLOTS },
	{ "sign",            0, NULL, OPT_SIGN },
	{ "slot",            1, NULL, OPT_SLOT },
	{ "threads",         1, NULL, OPT_THREADS },
	{ "version",         0, NULL, OPT_VERSION },
	{ NULL,              0, NULL, 0 }
};

CK_FUNCTION_LIST_PTR p11;

// The main function
int main(int argc, char* argv[])
{
	int option_index = 0;
	int opt;

	char* errMsg = NULL;
	char* iterations = NULL;
	char* keysize = NULL;
	char* mechanism = NULL;
	char* module = NULL;
	char* slot = NULL;
	char* threads = NULL;
	char* userPIN = NULL;

	int doShowSlots = 0;
	int doSign = 0;
	int action = 0;
	int rv = 0;

	moduleHandle = NULL;
	p11 = NULL;

	while ((opt = getopt_long(argc, argv, "hv", long_options, &option_index)) != -1)
	{
		switch (opt)
		{
			case OPT_SHOW_SLOTS:
				doShowSlots = 1;
				action++;
				break;
			case OPT_SIGN:
				doSign = 1;
				action++;
				break;
			case OPT_ITERATIONS:
				iterations = optarg;
				break;
			case OPT_KEYSIZE:
				keysize = optarg;
				break;
			case OPT_MECHANISM:
				mechanism = optarg;
				break;
			case OPT_MODULE:
				module = optarg;
				break;
			case OPT_PIN:
				userPIN = optarg;
				break;
			case OPT_SLOT:
				slot = optarg;
				break;
			case OPT_THREADS:
				threads = optarg;
				break;
			case OPT_VERSION:
			case 'v':
				printf("%s\n", PACKAGE_VERSION);
				exit(0);
				break;
			case OPT_HELP:
			case 'h':
			default:
				usage();
				exit(0);
				break;
		}
	}

	// No action given, display the usage.
	if (!action)
	{
		usage();
	}
	else
	{
		// Get a pointer to the function list for PKCS#11 library
		CK_C_GetFunctionList pGetFunctionList = loadLibrary(module, &moduleHandle, &errMsg);
		if (!pGetFunctionList)
		{
			fprintf(stderr, "ERROR: Could not load the library: %s\n", errMsg);
			exit(1);
		}

		// Load the function list
		(*pGetFunctionList)(&p11);

		// Initialize the library
		CK_C_INITIALIZE_ARGS initArgs = { NULL, NULL, NULL, NULL, CKF_OS_LOCKING_OK, NULL };
		CK_RV p11rv = p11->C_Initialize((CK_VOID_PTR) &initArgs);
		if (p11rv != CKR_OK)
		{
			fprintf(stderr, "ERROR: Could not initialize the library.\n");
			exit(1);
		}
	}

	// Show all available slots
	if (doShowSlots)
	{
		rv = showSlots();
	}

	// Sign operation
	if (doSign)
	{
		if (slot == NULL)
		{
			fprintf(stderr, "ERROR: A slot number must be supplied. "
					"Use --slot <number>\n");
			return 1;
		}
		if (threads == NULL)
		{
			fprintf(stderr, "ERROR: The number of threads must be supplied. "
					"Use --threads <number>\n");
			return 1;
		}
		if (iterations == NULL)
		{
			fprintf(stderr, "ERROR: The number of iterations must be supplied. "
					"Use --iterations <number>\n");
			return 1;
		}

		rv = testSign(atoi(slot), userPIN, mechanism, keysize,
			      atoi(threads), atoi(iterations));
	}

	// Finalize the library
	if (action)
	{
		p11->C_Finalize(NULL_PTR);
		unloadLibrary(moduleHandle);
	}

	return rv;
}

// Show what slots are available
int showSlots()
{
	CK_ULONG ulSlotCount;
	CK_RV rv = p11->C_GetSlotList(CK_FALSE, NULL_PTR, &ulSlotCount);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not get the number of slots.\n");
		return 1;
	}

	CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR) malloc(ulSlotCount*sizeof(CK_SLOT_ID));
	if (!pSlotList)
	{
		fprintf(stderr, "ERROR: Could not allocate memory.\n");
		return 1;
	}

	rv = p11->C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not get the slot list.\n");
		free(pSlotList);
		return 1;
	}

	printf("Available slots:\n");

	for (CK_ULONG i = 0; i < ulSlotCount; i++)
	{
		CK_SLOT_INFO slotInfo;
		CK_TOKEN_INFO tokenInfo;

		rv = p11->C_GetSlotInfo(pSlotList[i], &slotInfo);
		if (rv != CKR_OK)
		{
			fprintf(stderr, "ERROR: Could not get info about slot %lu.\n", pSlotList[i]);
			continue;
		}

		printf("Slot %lu\n", pSlotList[i]);
		printf("    Slot info:\n");
		printf("        Description:      %.*s\n", 64, slotInfo.slotDescription);
		printf("        Manufacturer ID:  %.*s\n", 32, slotInfo.manufacturerID);
		printf("        Hardware version: %i.%i\n", slotInfo.hardwareVersion.major,
							    slotInfo.hardwareVersion.minor);
		printf("        Firmware version: %i.%i\n", slotInfo.firmwareVersion.major,
							    slotInfo.firmwareVersion.minor);
		printf("        Token present:    ");
		if ((slotInfo.flags & CKF_TOKEN_PRESENT) == 0)
		{
			printf("no\n");
			continue;
		}

		printf("yes\n");
		printf("    Token info:\n");

		rv = p11->C_GetTokenInfo(pSlotList[i], &tokenInfo);
		if (rv != CKR_OK)
		{
			fprintf(stderr, "ERROR: Could not get info about the token in slot %lu.\n",
				pSlotList[i]);
			continue;
		}

		printf("        Manufacturer ID:  %.*s\n", 32, tokenInfo.manufacturerID);
		printf("        Model:            %.*s\n", 16, tokenInfo.model);
		printf("        Hardware version: %i.%i\n", tokenInfo.hardwareVersion.major,
							    tokenInfo.hardwareVersion.minor);
		printf("        Firmware version: %i.%i\n", tokenInfo.firmwareVersion.major,
							    tokenInfo.firmwareVersion.minor);
		printf("        Serial number:    %.*s\n", 16, tokenInfo.serialNumber);
		printf("        Initialized:      ");
		if ((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == 0)
		{
			printf("no\n");
		}
		else
		{
			printf("yes\n");
		}

		printf("        User PIN init.:   ");
		if ((tokenInfo.flags & CKF_USER_PIN_INITIALIZED) == 0)
		{
			printf("no\n");
		}
		else
		{
			printf("yes\n");
		}

		printf("        Label:            %.*s\n", 32, tokenInfo.label);

	}

	free(pSlotList);

	return 0;
}

// Benchmark signing operations
int testSign
(
	unsigned int slot,
	char* userPIN,
	char* mechanism,
	char* keysize,
	unsigned int threads,
	unsigned int iterations
)
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRO = CK_INVALID_HANDLE;
	CK_SESSION_HANDLE hSessionRW = CK_INVALID_HANDLE;
	CK_MECHANISM_TYPE mechanismType = CKM_VENDOR_DEFINED;
	CK_OBJECT_HANDLE hPublicKey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrivateKey = CK_INVALID_HANDLE;

	char user_pin_copy[MAX_PIN_LEN+1];
	sign_arg_t sign_arg_array[PTHREAD_THREADS_MAX];
	pthread_t thread_array[PTHREAD_THREADS_MAX];
	pthread_attr_t thread_attr;
	void* thread_status;
	unsigned int n, bits = 0;
	static struct timeval start,end;
	double elapsed, speed;
	int result = 1;
	HashAlgo::Type hashType = HashAlgo::Unknown;

	if (mechanism == NULL)
	{
		fprintf(stderr, "ERROR: A mechanism must be supplied. "
				"Use --mechanism <mech>\n");
		return 1;
	}

	// Open read-write session
	rv = p11->C_OpenSession((CK_SLOT_ID)slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
				NULL_PTR, NULL_PTR, &hSessionRW);
	if (rv != CKR_OK)
	{
		if (rv == CKR_SLOT_ID_INVALID)
		{
			fprintf(stderr, "ERROR: The given slot does not exist.\n");
		}
		else if (rv == CKR_TOKEN_NOT_RECOGNIZED)
		{
			fprintf(stderr, "ERROR: The token in the given slot has "
					"not been initialized.\n");
		}
		else
		{
			fprintf(stderr,
				"C_OpenSession() returned error: rv=%X\n",
				(unsigned int)rv);
		}
		return 1;
	}

	// Get the password
	getPW(userPIN, user_pin_copy, CKU_USER);

	// Login USER into the sessions so we can create private objects
	rv = p11->C_Login(hSessionRW, CKU_USER, (CK_UTF8CHAR_PTR)user_pin_copy,
			  strlen(user_pin_copy));
	if (rv != CKR_OK)
	{
		if (rv == CKR_PIN_INCORRECT)
		{
			fprintf(stderr, "ERROR: The given user PIN does not match "
					"the one in the token.\n");
		}
		else
		{
			fprintf(stderr,
				"C_Login() returned error: rv=%X\n",
				(unsigned int)rv);
		}
		return 1;
	}

	// Generate key
	if (strcmp(mechanism, "RSA_PKCS") == 0)
	{
		if (keysize == NULL)
		{
			fprintf(stderr, "ERROR: A key size must be supplied. "
					"Use --keysize <bits>\n");
			return 1;
		}

		bits = atoi(keysize);
		if (bits < 1024 || bits > 4096)
		{
			fprintf(stderr, "ERROR: Invalid key size: "
					"%i [1024-4096]\n", bits);
			return 1;
		}

		mechanismType = CKM_RSA_PKCS;
		hashType = HashAlgo::SHA256;
		result = generateRsa(hSessionRW, bits, hPublicKey, hPrivateKey);
	}
	else if (strcmp(mechanism, "DSA") == 0)
	{
		if (keysize == NULL)
		{
			fprintf(stderr, "ERROR: A key size must be supplied. "
					"Use --keysize <bits>\n");
			return 1;
		}

		bits = atoi(keysize);
		if (bits < 1024 || bits > 4096)
		{
			fprintf(stderr, "ERROR: Invalid key size: "
					"%i [1024-4096]\n", bits);
			return 1;
		}

		mechanismType = CKM_DSA;
		hashType = HashAlgo::SHA256;
		result = generateDsa(hSessionRW, bits, hPublicKey, hPrivateKey);
	}
	else if (strcmp(mechanism, "ECDSA") == 0)
	{
		if (keysize == NULL)
		{
			fprintf(stderr, "ERROR: A key size must be supplied. "
					"Use --keysize <bits>\n");
			return 1;
		}

		bits = atoi(keysize);
		if (bits == 256)
		{
			hashType = HashAlgo::SHA256;
		}
		else if (bits == 384)
		{
			hashType = HashAlgo::SHA384;
		}
		else
		{
			fprintf(stderr, "ERROR: Invalid key size: "
					"%i [256, 384]\n", bits);
			return 1;
		}

		mechanismType = CKM_ECDSA;
		result = generateEcdsa(hSessionRW, bits, hPublicKey, hPrivateKey);

	}
	else if (strcmp(mechanism, "GOSTR3410") == 0)
	{
		mechanismType = CKM_GOSTR3410;
		hashType = HashAlgo::GOST;
		result = generateGost(hSessionRW, hPublicKey, hPrivateKey);
	}
	else
	{
		fprintf(stderr, "ERROR: Unknown signing mechanism. "
				"Please edit --mechanism <mech> to correct the error.\n");
		return 1;
	}

	if (result != 0) return result;

	/* Prepare threads */
	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_JOINABLE);

	for (n=0; n<threads; n++)
	{
		rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO);
		if (rv != CKR_OK)
		{
			fprintf(stderr,
				"C_OpenSession() returned error: rv=%X\n",
				(unsigned int)rv);
			return 1;
		}

		sign_arg_array[n].id = n;
		sign_arg_array[n].iterations = iterations;
		sign_arg_array[n].hSession = hSessionRO;
		sign_arg_array[n].hPrivateKey = hPrivateKey;
		sign_arg_array[n].mechanismType = mechanismType;
		sign_arg_array[n].hashType = hashType;
	}

	fprintf(stderr, "Creating %d signatures with %s using %d %s...\n",
		iterations, mechanism, threads, (threads > 1 ? "threads" : "thread"));
	gettimeofday(&start, NULL);

	/* Create threads for signing */
	for (n=0; n<threads; n++)
	{
		result = pthread_create(&thread_array[n], &thread_attr,
					sign, (void *) &sign_arg_array[n]);
		if (result)
		{
			fprintf(stderr, "pthread_create() returned %d\n", result);
			return 1;
		}
	}

	/* Wait for threads to finish */
	for (n=0; n<threads; n++)
	{
		result = pthread_join(thread_array[n], &thread_status);
		if (result)
		{
			fprintf(stderr, "pthread_join() returned %d\n", result);
			return 1;
		}
	}

	gettimeofday(&end, NULL);

	/* Report results */
	end.tv_sec -= start.tv_sec;
	end.tv_usec-= start.tv_usec;
	elapsed =(double)(end.tv_sec)+(double)(end.tv_usec)*.000001;
	speed = iterations / elapsed * threads;
	if (bits)
	{
		printf("%d %s, %d signatures per thread, %.2f sig/s (%s %i bits)\n",
		       threads, (threads > 1 ? "threads" : "thread"), iterations,
		       speed, mechanism, bits);
	}
	else
	{
		printf("%d %s, %d signatures per thread, %.2f sig/s (%s)\n",
		       threads, (threads > 1 ? "threads" : "thread"), iterations,
		       speed, mechanism);
	}

	// Remove key
	rv = p11->C_DestroyObject(hSessionRW, hPublicKey);
	if (rv != CKR_OK)
	{
		fprintf(stderr,
			"C_DestroyObject() returned error: rv=%X\n",
			(unsigned int)rv);
		return 1;
	}
	rv = p11->C_DestroyObject(hSessionRW, hPrivateKey);
	if (rv != CKR_OK)
	{
		fprintf(stderr,
			"C_DestroyObject() returned error: rv=%X\n",
			(unsigned int)rv);
		return 1;
	}

	return 0;
}

int generateRsa(CK_SESSION_HANDLE hSession, CK_ULONG keysize, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
{
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_MECHANISM mechanism = {
		CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
	};
	CK_BYTE pubExp[] = { 0x01, 0x00, 0x01 };
	CK_BYTE label[] = { 0x70, 0x31, 0x31, 0x73, 0x70, 0x65, 0x65, 0x64 }; // p11speed
	CK_BYTE id[] = { 0x12, 0x34 };
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;

	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_LABEL,           &label[0], sizeof(label)   },
		{ CKA_ID,              &id[0],    sizeof(id)      },
		{ CKA_KEY_TYPE,        &keyType,  sizeof(keyType) },
		{ CKA_VERIFY,          &bTrue,    sizeof(bTrue)   },
		{ CKA_ENCRYPT,         &bFalse,   sizeof(bFalse)  },
		{ CKA_WRAP,            &bFalse,   sizeof(bFalse)  },
		{ CKA_TOKEN,           &bTrue,    sizeof(bTrue)   },
		{ CKA_MODULUS_BITS,    &keysize,  sizeof(keysize) },
		{ CKA_PUBLIC_EXPONENT, &pubExp,   sizeof(pubExp)  }
	};

	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_LABEL,       &label[0], sizeof(label)   },
		{ CKA_ID,          &id[0],    sizeof(id)      },
		{ CKA_KEY_TYPE,    &keyType,  sizeof(keyType) },
		{ CKA_SIGN,        &bTrue,    sizeof(bTrue)   },
		{ CKA_DECRYPT,     &bFalse,   sizeof(bFalse)  },
		{ CKA_UNWRAP,      &bFalse,   sizeof(bFalse)  },
		{ CKA_SENSITIVE,   &bTrue,    sizeof(bTrue)   },
		{ CKA_TOKEN,       &bTrue,    sizeof(bTrue)   },
		{ CKA_PRIVATE,     &bTrue,    sizeof(bTrue)   },
		{ CKA_EXTRACTABLE, &bFalse,   sizeof(bFalse)  }
	};

	CK_RV rv = p11->C_GenerateKeyPair(hSession, &mechanism,
					  pukAttribs, 9,
					  prkAttribs, 10,
					  &hPuk, &hPrk);
	if (rv != CKR_OK)
	{
		fprintf(stderr,
			"C_GenerateKeyPair() returned error: rv=%X\n",
			(unsigned int)rv);
		return 1;
	}

	return 0;
}

int generateDsa(CK_SESSION_HANDLE hSession, CK_ULONG keysize, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
{
	CK_KEY_TYPE keyType = CKK_DSA;
	CK_MECHANISM mechanism1 = {
		CKM_DSA_PARAMETER_GEN, NULL_PTR, 0
	};
	CK_MECHANISM mechanism2 = {
		CKM_DSA_KEY_PAIR_GEN, NULL_PTR, 0
	};

	CK_BYTE label[] = { 0x70, 0x31, 0x31, 0x73, 0x70, 0x65, 0x65, 0x64 }; // p11speed
	CK_BYTE id[] = { 0x12, 0x34 };
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;

	CK_BYTE dsa_p[512];
	CK_BYTE dsa_q[32];
	CK_BYTE dsa_g[512];

	CK_ATTRIBUTE domainTemplate[] = {
		{ CKA_PRIME_BITS, &keysize, sizeof(keysize) }
	};
	CK_OBJECT_HANDLE domainPar;

	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_PRIME,    dsa_p,     sizeof(dsa_p)   },
		{ CKA_SUBPRIME, dsa_q,     sizeof(dsa_q)   },
		{ CKA_BASE,     dsa_g,     sizeof(dsa_g)   },
		{ CKA_LABEL,    &label[0], sizeof(label)   },
		{ CKA_ID,       &id[0],    sizeof(id)      },
		{ CKA_KEY_TYPE, &keyType,  sizeof(keyType) },
		{ CKA_VERIFY,   &bTrue,    sizeof(bTrue)   },
		{ CKA_ENCRYPT,  &bFalse,   sizeof(bFalse)  },
		{ CKA_WRAP,     &bFalse,   sizeof(bFalse)  },
		{ CKA_TOKEN,    &bTrue,    sizeof(bTrue)   }
	};

	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_LABEL,       &label[0], sizeof(label)   },
		{ CKA_ID,          &id[0],    sizeof(id)      },
		{ CKA_KEY_TYPE,    &keyType,  sizeof(keyType) },
		{ CKA_SIGN,        &bTrue,    sizeof(bTrue)   },
		{ CKA_DECRYPT,     &bFalse,   sizeof(bFalse)  },
		{ CKA_UNWRAP,      &bFalse,   sizeof(bFalse)  },
		{ CKA_SENSITIVE,   &bTrue,    sizeof(bTrue)   },
		{ CKA_TOKEN,       &bTrue,    sizeof(bTrue)   },
		{ CKA_PRIVATE,     &bTrue,    sizeof(bTrue)   },
		{ CKA_EXTRACTABLE, &bFalse,   sizeof(bFalse)  }
	};

	CK_RV rv = p11->C_GenerateKey(hSession, &mechanism1,
				      domainTemplate, 1,
				      &domainPar);
	if (rv != CKR_OK)
	{
		fprintf(stderr,
			"C_GenerateKey() returned error: rv=%X\n",
			(unsigned int)rv);
		return 1;
	}

	rv = p11->C_GetAttributeValue(hSession, domainPar,
				      pukAttribs, 3);
	if (rv != CKR_OK)
	{
		fprintf(stderr,
			"C_GetAttributeValue() returned error: rv=%X\n",
			(unsigned int)rv);
		return 1;
	}

	rv = p11->C_DestroyObject(hSession, domainPar);
	if (rv != CKR_OK)
	{
		fprintf(stderr,
			"C_DestroyObject() returned error: rv=%X\n",
			(unsigned int)rv);
		return 1;
	}

	rv = p11->C_GenerateKeyPair(hSession, &mechanism2,
				    pukAttribs, 10,
				    prkAttribs, 10,
				    &hPuk, &hPrk);
	if (rv != CKR_OK)
	{
		fprintf(stderr,
			"C_GenerateKeyPair() returned error: rv=%X\n",
			(unsigned int)rv);
		return 1;
	}

	return 0;
}

int generateEcdsa(CK_SESSION_HANDLE hSession, CK_ULONG keysize, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
{
	CK_KEY_TYPE keyType = CKK_EC;
	CK_MECHANISM mechanism = {
		CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0
	};
	CK_BYTE oidP256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
	CK_BYTE oidP384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
	CK_BYTE label[] = { 0x70, 0x31, 0x31, 0x73, 0x70, 0x65, 0x65, 0x64 }; // p11speed
	CK_BYTE id[] = { 0x12, 0x34 };
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;

	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_EC_PARAMS, NULL,      0               },
		{ CKA_LABEL,     &label[0], sizeof(label)   },
		{ CKA_ID,        &id[0],    sizeof(id)      },
		{ CKA_KEY_TYPE,  &keyType,  sizeof(keyType) },
		{ CKA_VERIFY,    &bTrue,    sizeof(bTrue)   },
		{ CKA_ENCRYPT,   &bFalse,   sizeof(bFalse)  },
		{ CKA_WRAP,      &bFalse,   sizeof(bFalse)  },
		{ CKA_TOKEN,     &bTrue,    sizeof(bTrue)   }
	};

	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_LABEL,       &label[0], sizeof(label)   },
		{ CKA_ID,          &id[0],    sizeof(id)      },
		{ CKA_KEY_TYPE,    &keyType,  sizeof(keyType) },
		{ CKA_SIGN,        &bTrue,    sizeof(bTrue)   },
		{ CKA_DECRYPT,     &bFalse,   sizeof(bFalse)  },
		{ CKA_UNWRAP,      &bFalse,   sizeof(bFalse)  },
		{ CKA_SENSITIVE,   &bTrue,    sizeof(bTrue)   },
		{ CKA_TOKEN,       &bTrue,    sizeof(bTrue)   },
		{ CKA_PRIVATE,     &bTrue,    sizeof(bTrue)   },
		{ CKA_EXTRACTABLE, &bFalse,   sizeof(bFalse)  }
	};

	// Select the curve
	if (keysize == 256)
	{
		pukAttribs[0].pValue = oidP256;
		pukAttribs[0].ulValueLen = sizeof(oidP256);
	}
	else if (keysize == 384)
	{
		pukAttribs[0].pValue = oidP384;
		pukAttribs[0].ulValueLen = sizeof(oidP384);
	}
	else
	{
		fprintf(stderr, "generateEcdsa(): Invalid curve\n");
		return 1;
	}

	CK_RV rv = p11->C_GenerateKeyPair(hSession, &mechanism,
					  pukAttribs, 8,
					  prkAttribs, 10,
					  &hPuk, &hPrk);
	if (rv != CKR_OK)
	{
		fprintf(stderr,
			"C_GenerateKeyPair() returned error: rv=%X\n",
			(unsigned int)rv);
		return 1;
	}

	return 0;
}

int generateGost(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
{
	CK_KEY_TYPE keyType = CKK_GOSTR3410;
	CK_MECHANISM mechanism = {
		CKM_GOSTR3410_KEY_PAIR_GEN, NULL_PTR, 0
	};
	CK_BYTE oid1[] = { 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01 };
	CK_BYTE oid2[] = { 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x1E, 0x01 };
	CK_BYTE label[] = { 0x70, 0x31, 0x31, 0x73, 0x70, 0x65, 0x65, 0x64 }; // p11speed
	CK_BYTE id[] = { 0x12, 0x34 };
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;

	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_GOSTR3410_PARAMS, oid1,      sizeof(oid1)    },
		{ CKA_GOSTR3411_PARAMS, oid2,      sizeof(oid2)    },
		{ CKA_LABEL,            &label[0], sizeof(label)   },
		{ CKA_ID,               &id[0],    sizeof(id)      },
		{ CKA_KEY_TYPE,         &keyType,  sizeof(keyType) },
		{ CKA_VERIFY,           &bTrue,    sizeof(bTrue)   },
		{ CKA_ENCRYPT,          &bFalse,   sizeof(bFalse)  },
		{ CKA_WRAP,             &bFalse,   sizeof(bFalse)  },
		{ CKA_TOKEN,            &bTrue,    sizeof(bTrue)   }
	};

	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_LABEL,       &label[0], sizeof(label)   },
		{ CKA_ID,          &id[0],    sizeof(id)      },
		{ CKA_KEY_TYPE,    &keyType,  sizeof(keyType) },
		{ CKA_SIGN,        &bTrue,    sizeof(bTrue)   },
		{ CKA_DECRYPT,     &bFalse,   sizeof(bFalse)  },
		{ CKA_UNWRAP,      &bFalse,   sizeof(bFalse)  },
		{ CKA_SENSITIVE,   &bTrue,    sizeof(bTrue)   },
		{ CKA_TOKEN,       &bTrue,    sizeof(bTrue)   },
		{ CKA_PRIVATE,     &bTrue,    sizeof(bTrue)   },
		{ CKA_EXTRACTABLE, &bFalse,   sizeof(bFalse)  }
	};

	CK_RV rv = p11->C_GenerateKeyPair(hSession, &mechanism,
					  pukAttribs, 9,
					  prkAttribs, 10,
					  &hPuk, &hPrk);
	if (rv != CKR_OK)
	{
		fprintf(stderr,
			"C_GenerateKeyPair() returned error: rv=%X\n",
			(unsigned int)rv);
		return 1;
	}

	return 0;
}

void* sign (void* arg)
{
	sign_arg_t* sign_arg = (sign_arg_t*)arg;
	unsigned int id = sign_arg->id;
	unsigned int iterations = sign_arg->iterations;
	CK_SESSION_HANDLE hSession = sign_arg->hSession;
	CK_OBJECT_HANDLE hPrivateKey = sign_arg->hPrivateKey;
	CK_MECHANISM_TYPE mechanismType = sign_arg->mechanismType;
	HashAlgo::Type hashType = sign_arg->hashType;

	size_t i;
	CK_RV rv;
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	// SHA256(p11speed)= f2c55b2f6a9dc972d444278810c226faf22ff96b1abd248f0118fa700e2aed72
	CK_BYTE data256[] = { 0xf2, 0xc5, 0x5b, 0x2f, 0x6a, 0x9d, 0xc9, 0x72, 0xd4, 0x44,
			      0x27, 0x88, 0x10, 0xc2, 0x26, 0xfa, 0xf2, 0x2f, 0xf9, 0x6b,
			      0x1a, 0xbd, 0x24, 0x8f, 0x01, 0x18, 0xfa, 0x70, 0x0e, 0x2a,
			      0xed, 0x72 };
	// SHA384(p11speed)= 3aec14e31d63ff1f9b2afe7e51fa7fe79926466c80a5aea185a2112df6d31f7c7cd9fffe3bdcc04dcf02010316ab340f
	CK_BYTE data384[] = { 0x3a, 0xec, 0x14, 0xe3, 0x1d, 0x63, 0xff, 0x1f, 0x9b, 0x2a,
			      0xfe, 0x7e, 0x51, 0xfa, 0x7f, 0xe7, 0x99, 0x26, 0x46, 0x6c,
			      0x80, 0xa5, 0xae, 0xa1, 0x85, 0xa2, 0x11, 0x2d, 0xf6, 0xd3,
			      0x1f, 0x7c, 0x7c, 0xd9, 0xff, 0xfe, 0x3b, 0xdc, 0xc0, 0x4d,
			      0xcf, 0x02, 0x01, 0x03, 0x16, 0xab, 0x34, 0x0f };
	// GOSTR3411(p11speed)= 286e36119111e58338af8a821fff332d2211897f35dedcbaba488876b352553c
	CK_BYTE dataGost[] = { 0x28, 0x6e, 0x36, 0x11, 0x91, 0x11, 0xe5, 0x83, 0x38, 0xaf,
			       0x8a, 0x82, 0x1f, 0xff, 0x33, 0x2d, 0x22, 0x11, 0x89, 0x7f,
			       0x35, 0xde, 0xdc, 0xba, 0xba, 0x48, 0x88, 0x76, 0xb3, 0x52,
			       0x55, 0x3c };

	CK_BYTE* data;
	CK_ULONG ulDataLen = 0;
	switch (hashType)
	{
		case HashAlgo::SHA256:
		default:
			data = data256;
			ulDataLen = sizeof(data256);
			break;
		case HashAlgo::SHA384:
			data = data384;
			ulDataLen = sizeof(data384);
			break;
		case HashAlgo::GOST:
			data = dataGost;
			ulDataLen = sizeof(dataGost);
			break;
	}

	// 4096 / 8 = 512
	CK_BYTE signature[512];
	CK_ULONG ulSignatureLen = 0;

	fprintf(stderr, "Signer thread #%d started...\n", id);

	/* Do some signing */
	for (i=0; i<iterations; i++) {
		rv = p11->C_SignInit(hSession, &mechanism, hPrivateKey);
		if (rv != CKR_OK)
		{
			fprintf(stderr,
				"C_SignInit() returned error: rv=%X\n",
				(unsigned int)rv);
			break;
		}

		ulSignatureLen = sizeof(signature);
		rv = p11->C_Sign(hSession,
				 data,
				 ulDataLen,
				 signature,
				 &ulSignatureLen);
		if (rv != CKR_OK)
		{
			fprintf(stderr,
				"C_Sign() returned error: rv=%X\n",
				(unsigned int)rv);
			break;
		}
	}

	fprintf(stderr, "Signer thread #%d done.\n", id);

	pthread_exit(NULL);
}
