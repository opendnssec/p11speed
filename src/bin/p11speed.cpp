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
#endif
#include <iostream>
#include <fstream>

// Display the usage
void usage()
{
	printf("Speed test for PKCS#11\n");
	printf("Usage: p11speed [ACTION] [OPTIONS]\n");
	printf("Action:\n");
	printf("  -h                Shows this help screen.\n");
	printf("  --help            Shows this help screen.\n");
	printf("  --show-slots      Display all the available slots.\n");
	printf("  -v                Show version info.\n");
	printf("  --version         Show version info.\n");
	printf("Options:\n");
	printf("  --module <path>   Use another PKCS#11 library than SoftHSM.\n");
	printf("  --pin <PIN>       The PIN for the normal user.\n");
	printf("  --slot <number>   The slot where the token is located.\n");
}

// Enumeration of the long options
enum {
	OPT_HELP = 0x100,
	OPT_MODULE,
	OPT_PIN,
	OPT_SHOW_SLOTS,
	OPT_SLOT,
	OPT_VERSION
};

// Text representation of the long options
static const struct option long_options[] = {
	{ "help",            0, NULL, OPT_HELP },
	{ "module",          1, NULL, OPT_MODULE },
	{ "pin",             1, NULL, OPT_PIN },
	{ "show-slots",      0, NULL, OPT_SHOW_SLOTS },
	{ "slot",            1, NULL, OPT_SLOT },
	{ "version",         0, NULL, OPT_VERSION },
	{ NULL,              0, NULL, 0 }
};

CK_FUNCTION_LIST_PTR p11;

// The main function
int main(int argc, char* argv[])
{
	int option_index = 0;
	int opt;

	char* userPIN = NULL;
	char* module = NULL;
	char* slot = NULL;
	char* errMsg = NULL;

	int doShowSlots = 0;
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
			case OPT_SLOT:
				slot = optarg;
				break;
			case OPT_MODULE:
				module = optarg;
				break;
			case OPT_PIN:
				userPIN = optarg;
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
		CK_RV p11rv = p11->C_Initialize(NULL_PTR);
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
