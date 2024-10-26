#include "SSDTFunction.h"


// ��ȡ SSDT ������ַ
//Callers must be running at IRQL = PASSIVE_LEVEL and with special kernel APCs enabled
//��Ϊʹ����ZwOpenFile
PVOID GetSSDTFunction(PCHAR pszFunctionName)
{
	UNICODE_STRING ustrDllFileName;
	ULONG ulSSDTFunctionIndex = 0;
	PVOID pFunctionAddress = NULL;
	PSSDTEntry pServiceDescriptorTable = NULL;
	ULONG ulOffset = 0;
	
	RtlInitUnicodeString(&ustrDllFileName, L"\\??\\C:\\Windows\\System32\\ntdll.dll");
	// �� ntdll.dll �л�ȡ SSDT ����������
	ulSSDTFunctionIndex = GetSSDTFunctionIndex(ustrDllFileName, pszFunctionName);

	//32λ, ֱ�ӻ�ȡ������ַ; 64λ, ����������, �� KiSystemCall64 �л�ȡ SSDT ��ַ
	pServiceDescriptorTable = (PSSDTEntry)GetSSDTAddress();
	if (!pServiceDescriptorTable)
		return NULL;

	// ����������, ��SSDT���л�ȡ��Ӧ����ƫ�Ƶ�ַ�������������ַ
#ifndef _WIN64
	// 32 Bits
	pFunctionAddress = (PVOID)pServiceDescriptorTable->ServiceTableBase[ulSSDTFunctionIndex];
#else
	// 64 Bits
	ulOffset = pServiceDescriptorTable->ServiceTableBase[ulSSDTFunctionIndex] >> 4;
	pFunctionAddress = (PVOID)((PUCHAR)pServiceDescriptorTable->ServiceTableBase + ulOffset);
#endif

	// ��ʾ
	DbgPrint("[%s][SSDT Addr:0x%p][Index:%d][Address:0x%p]\n", pszFunctionName, pServiceDescriptorTable, ulSSDTFunctionIndex, pFunctionAddress);

	return pFunctionAddress;
}

ULONGLONG SearchforKeServiceDescriptorTable64(ULONGLONG StartSearchAddress, ULONGLONG EndSearchAddress)
{
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONG templong = 0;
	PUCHAR i;
	ULONGLONG KeServiceDescriptorTable = 0;

	//��ַЧ��
	if (MmIsAddressValid((PVOID)StartSearchAddress) == FALSE)
		return 0;
	if (MmIsAddressValid((PVOID)EndSearchAddress) == FALSE)
		return 0;

	for (i = (PUCHAR)StartSearchAddress; i < (PUCHAR)EndSearchAddress; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			b1 = *i;
			b2 = *(i + 1);
			b3 = *(i + 2);
			//DbgPrint("0x%p: 0x%x 0x%x 0x%x\r\n", i, b1, b2, b3);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15)  //4c8d15
			{
				memcpy(&templong, i + 3, 4);
				KeServiceDescriptorTable = (ULONGLONG)templong + (ULONGLONG)i + 7;
				return KeServiceDescriptorTable;
				//��ǰ��ַ + ���� + ��ֵ
				//fffff800`03c8c772+7 + 002320c7 = FFFFF80003EBE840
				/*
				fffff800`03c8c772 4c8d15c7202300  lea     r10,[nt!KeServiceDescriptorTable (fffff800`03ebe840)]
				fffff800`03c8c779 4c8d1d00212300  lea     r11,[nt!KeServiceDescriptorTableShadow (fffff800`03ebe880)]
				*/
			}
		}
	}
	return 0;
}

//��ȡSSDT KeServiceDescriptorTable
ULONGLONG GetKeServiceDescriptorTable64()
{
	PUCHAR EndSearchAddress;
	ULONGLONG KeServiceDescriptorTable = 0;
	//msr[0xc0000082]�����KiSystemCall64Shadow����
	//ԭ������64λ����KeServiceDescriptorTable��ͨ��msr��0xc0000082���KiSystemCall64�ֶ�, ��������msr[0xc0000082]�����KiSystemCall64Shadow����, ������������޷�ֱ��������KeServiceDescriptorTable��
	ULONGLONG KiSystemServiceUser = 0;
	ULONGLONG templong = 0xffffffffffffffff;
	PUCHAR i;
	PUCHAR pKiSystemCall64 = (PUCHAR)__readmsr(0xc0000082);  //rdmsr c0000082   //��λKiSystemCall64
	EndSearchAddress = pKiSystemCall64 + 0x500;

	KeServiceDescriptorTable = SearchforKeServiceDescriptorTable64((ULONGLONG)pKiSystemCall64, (ULONGLONG)EndSearchAddress);
	if (KeServiceDescriptorTable)
		return  KeServiceDescriptorTable;

	for (i = pKiSystemCall64; i < EndSearchAddress + 0xff; i++)
	{
		if (*(PUCHAR)i == 0xe9 && *(PUCHAR)(i + 5) == 0xc3)
		{
			//fffff803`23733383 e9631ae9ff      jmp     nt!KiSystemServiceUser(fffff803`235c4deb)
			//fffff803`23733388 c3              ret
			RtlCopyMemory(&templong, (PUCHAR)(i + 1), 4);
			KiSystemServiceUser = templong + 5 + (ULONGLONG)i;//KiSystemServiceUser
			EndSearchAddress = (PUCHAR)KiSystemServiceUser + 0x500;
			KeServiceDescriptorTable = SearchforKeServiceDescriptorTable64(KiSystemServiceUser, (ULONGLONG)EndSearchAddress);
			return KeServiceDescriptorTable;
		}
	}
	return 0;
}


// 32λ, ֱ�ӻ�ȡ������ַ; 64λ, ����������, �� KiSystemCall64 �л�ȡ SSDT ��ַ
PVOID GetSSDTAddress()
{
	PVOID pServiceDescriptorTable = NULL;
	// ע��ʹ���з�������
	LONG lOffset = 0, i = 0;

#ifndef _WIN64
	// 32 Bits
	pServiceDescriptorTable = (PVOID)(&KeServiceDescriptorTable);
#else
	//��ʱע��
	//// 64 Bits
	//// ��ȡ KiSystemCall64 ������ַ 
	//pKiSystemCall64 = (PVOID)__readmsr(0xC0000082);
	//// ���������� 4C8D15
	//for (i = 0; i < 0x500; i++) //�����С����Ҫ�޸�
	//{
	//	// ��ȡ�ڴ�����
	//	ulCode1 = *((PUCHAR)((PUCHAR)pKiSystemCall64 + i));
	//	ulCode2 = *((PUCHAR)((PUCHAR)pKiSystemCall64 + i + 1));
	//	ulCode3 = *((PUCHAR)((PUCHAR)pKiSystemCall64 + i + 2));
	//	// �ж�
	//	if (0x4C == ulCode1 &&
	//		0x8D == ulCode2 &&
	//		0x15 == ulCode3)
	//	{
	//		// ��ȡƫ��
	//		lOffset = *((PLONG)((PUCHAR)pKiSystemCall64 + i + 3));
	//		// ����ƫ�Ƽ����ַ
	//		pServiceDescriptorTable = (PVOID)(((PUCHAR)pKiSystemCall64 + i) + 7 + lOffset);
	//		DbgPrint("GetSSDTAddress �ҵ�ssdt!\r\n");
	//		break;
	//	}
	//}

	pServiceDescriptorTable = (PVOID)GetKeServiceDescriptorTable64();
#endif

	return pServiceDescriptorTable;
}


// �� ntdll.dll �л�ȡ SSDT ����������
ULONG GetSSDTFunctionIndex(UNICODE_STRING ustrDllFileName, PCHAR pszFunctionName)
{
	ULONG ulFunctionIndex = 0;
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	PVOID pBaseAddress = NULL;

	// �ڴ�ӳ���ļ�
	status = DllFileMap(ustrDllFileName, &hFile, &hSection, &pBaseAddress);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("DllFileMap Error!\n"));
		return ulFunctionIndex;
	}

	// ���ݵ������ȡ����������ַ, �Ӷ���ȡ SSDT ����������
	ulFunctionIndex = GetIndexFromExportTable(pBaseAddress, pszFunctionName);

	// �ͷ�
	ZwUnmapViewOfSection(NtCurrentProcess(), pBaseAddress);
	ZwClose(hSection);
	ZwClose(hFile);

	return ulFunctionIndex;
}

// �ڴ�ӳ���ļ�
NTSTATUS DllFileMap(UNICODE_STRING ustrDllFileName, HANDLE *phFile, HANDLE *phSection, PVOID *ppBaseAddress)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	IO_STATUS_BLOCK iosb = { 0 };
	PVOID pBaseAddress = NULL;
	SIZE_T viewSize = 0;
	// �� DLL �ļ�, ����ȡ�ļ����
	InitializeObjectAttributes(&objectAttributes, &ustrDllFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	//Callers of ZwOpenFile must be running at IRQL = PASSIVE_LEVEL and with special kernel APCs enabled
	status = ZwOpenFile(&hFile, GENERIC_READ, &objectAttributes, &iosb,
		FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("ZwOpenFile Error! [error code: 0x%X]", status));
		return status;
	}
	// ����һ���ڶ���, �� PE �ṹ�е� SectionALignment ��С����ӳ���ļ�
	status = ZwCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, 0, PAGE_READWRITE, 0x1000000, hFile);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		KdPrint(("ZwCreateSection Error! [error code: 0x%X]", status));
		return status;
	}
	// ӳ�䵽�ڴ�
	status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &pBaseAddress, 0, 1024, 0, &viewSize, ViewShare, MEM_TOP_DOWN, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hSection);
		ZwClose(hFile);
		KdPrint(("ZwMapViewOfSection Error! [error code: 0x%X]", status));
		return status;
	}

	// ��������
	*phFile = hFile;
	*phSection = hSection;
	*ppBaseAddress = pBaseAddress;

	return status;
}

// ���ݵ������ȡ����������ַ, �Ӷ���ȡ SSDT ����������
ULONG GetIndexFromExportTable(PVOID pBaseAddress, PCHAR pszFunctionName)
{
	ULONG ulFunctionIndex = 0;
	// Dos Header
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	// NT Header
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
	// Export Table
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	// �����Ƶĵ�����������
	ULONG ulNumberOfNames = pExportTable->NumberOfNames;
	// �����������Ƶ�ַ��
	PULONG lpNameArray = (PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfNames);
	PCHAR lpName = NULL;
	ULONG i = 0;
	// ��ʼ����������
	for (i = 0; i < ulNumberOfNames; i++)
	{
		lpName = (PCHAR)((PUCHAR)pDosHeader + lpNameArray[i]);
		// �ж��Ƿ���ҵĺ���
		if (0 == _strnicmp(pszFunctionName, lpName, strlen(pszFunctionName)))
		{
			// ��ȡ����������ַ
			USHORT uHint = *(USHORT *)((PUCHAR)pDosHeader + pExportTable->AddressOfNameOrdinals + 2 * i);
			ULONG ulFuncAddr = *(PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfFunctions + 4 * uHint);
			PVOID lpFuncAddr = (PVOID)((PUCHAR)pDosHeader + ulFuncAddr);
			// ��ȡ SSDT ���� Index
#ifdef _WIN64
			ulFunctionIndex = *(ULONG *)((PUCHAR)lpFuncAddr + 4);
#else
			ulFunctionIndex = *(ULONG *)((PUCHAR)lpFuncAddr + 1);
#endif
			break;
		}
	}

	return ulFunctionIndex;
}