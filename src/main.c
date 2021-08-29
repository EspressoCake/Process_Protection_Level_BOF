/**
  Copyright © 2019-2020 Odzhan. All Rights Reserved.
  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:
  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.
  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.
  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#ifndef _WIN64
#error You must use a 64-bit version of MSVC
#endif

#pragma warning(disable : 4047)

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "beacon.h"
#include "syscalls.h"


void go(char* args, int length) {
    char* sc_ptr;
    DWORD processID;
    datap parser;

    BeaconDataParse(&parser, args, length);
    processID = BeaconDataInt(&parser);

    HANDLE assumedProcessHandle = NULL;

    OBJECT_ATTRIBUTES oa  = {sizeof(oa)};
    CLIENT_ID         cid = { 0 };
    cid.UniqueProcess     = processID;

    NTSTATUS handleResult = ZwOpenProcess(&assumedProcessHandle, 0x1000, &oa, &cid);
    
    if (!handleResult) {
        PS_PROTECTION protectionStruct = { 0 };
        NTSTATUS protectionResult = ZwQueryInformationProcess(assumedProcessHandle, (PROCESSINFOCLASS)61, &protectionStruct, sizeof(protectionStruct), NULL);

        if (protectionResult == 0) {
                unsigned int protectionType   = (unsigned int)protectionStruct.Type;
                unsigned int protectionSigner = (unsigned int)protectionStruct.Signer;
                
                switch (protectionType) {
                    case 0:
                        BeaconPrintf(CALLBACK_OUTPUT, "Type: PsProtectedTypeNone\n");
                        break;
                    case 1:
                        BeaconPrintf(CALLBACK_OUTPUT, "Type: PsProtectedTypeProtectedLight\n");
                        break;
                    case 2:
                        BeaconPrintf(CALLBACK_OUTPUT, "Type: PsProtectedTypeProtected\n");
                        break;
                    default:
                        break;
                }

                switch(protectionSigner) {
                    case 0:
                        BeaconPrintf(CALLBACK_OUTPUT, "Signer: PsProtectedSignerNone\n");
                        break;
                    case 4:
                        BeaconPrintf(CALLBACK_OUTPUT, "Signer: PsProtectedSignerLsa\n");
                        break;
                }

                ZwClose(assumedProcessHandle);

                return;

        } else {
            BeaconPrintf(CALLBACK_ERROR, "ZwQueryInformation process failed with supplied handle.");
            ZwClose(assumedProcessHandle);
            
            return;
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Unable to derive handle to specified process.");
        return;
    }

}