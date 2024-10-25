#pragma once
#include "util.h"
#include <ntstrsafe.h>
#include <stdlib.h>
#include <time.h>
#include "SSDTFunction.h"
#include "base.h"

namespace n_smbios
{
	char smbois_vendor[100]{ 0 };
	char smbois_version[100]{ 0 };
	char smbois_date[100]{ 0 };
	char smbois_manufacturer[100]{ 0 };
	char smbois_product_name[100]{ 0 };
	char smbois_serial_number[100]{ 0 };

	PDRIVER_OBJECT g_DriverObject = NULL;
	extern "C" POBJECT_TYPE IoDriverObjectType;
	PDRIVER_OBJECT g_PnpDriverObject = NULL;
	//extern "C" PDRIVER_OBJECT IoPnpDriverObject;

#pragma pack(1)
	typedef struct
	{
		UINT8   Type;
		UINT8   Length;
		UINT8   Handle[2];
	} SMBIOS_HEADER,*PSMBIOS_HEADER;

	typedef UINT8   SMBIOS_STRING;

	typedef struct
	{
		SMBIOS_HEADER   Hdr;
		SMBIOS_STRING   Vendor;
		SMBIOS_STRING   BiosVersion;
		UINT8           BiosSegment[2];
		SMBIOS_STRING   BiosReleaseDate;
		UINT8           BiosSize;
		UINT8           BiosCharacteristics[8];
	} SMBIOS_TYPE0;

	typedef struct
	{
		SMBIOS_HEADER   Hdr;
		SMBIOS_STRING   Manufacturer;
		SMBIOS_STRING   ProductName;
		SMBIOS_STRING   Version;
		SMBIOS_STRING   SerialNumber;

		//
		// always byte copy this data to prevent alignment faults!
		//
		GUID			Uuid; // EFI_GUID == GUID?

		UINT8           WakeUpType;
	} SMBIOS_TYPE1;

	typedef struct
	{
		SMBIOS_HEADER   Hdr;
		SMBIOS_STRING   Manufacturer;
		SMBIOS_STRING   ProductName;
		SMBIOS_STRING   Version;
		SMBIOS_STRING   SerialNumber;
	} SMBIOS_TYPE2;

	typedef struct
	{
		SMBIOS_HEADER   Hdr;
		SMBIOS_STRING   Manufacturer;
		UINT8           Type;
		SMBIOS_STRING   Version;
		SMBIOS_STRING   SerialNumber;
		SMBIOS_STRING   AssetTag;
		UINT8           BootupState;
		UINT8           PowerSupplyState;
		UINT8           ThermalState;
		UINT8           SecurityStatus;
		UINT8           OemDefined[4];
	} SMBIOS_TYPE3;

	//CPU
	typedef struct {
		UINT32    ProcessorSteppingId : 4;
		UINT32    ProcessorModel : 4;
		UINT32    ProcessorFamily : 4;
		UINT32    ProcessorType : 2;
		UINT32    ProcessorReserved1 : 2;
		UINT32    ProcessorXModel : 4;
		UINT32    ProcessorXFamily : 8;
		UINT32    ProcessorReserved2 : 4;
	} PROCESSOR_SIGNATURE;

	typedef struct {
		UINT8    ProcessorVoltageCapability5V : 1;
		UINT8    ProcessorVoltageCapability3_3V : 1;
		UINT8    ProcessorVoltageCapability2_9V : 1;
		UINT8    ProcessorVoltageCapabilityReserved : 1; ///< Bit 3, must be zero.
		UINT8    ProcessorVoltageReserved : 3; ///< Bits 4-6, must be zero.
		UINT8    ProcessorVoltageIndicateLegacy : 1;
	} PROCESSOR_VOLTAGE;

	typedef struct {
		UINT32    ProcessorFpu : 1;
		UINT32    ProcessorVme : 1;
		UINT32    ProcessorDe : 1;
		UINT32    ProcessorPse : 1;
		UINT32    ProcessorTsc : 1;
		UINT32    ProcessorMsr : 1;
		UINT32    ProcessorPae : 1;
		UINT32    ProcessorMce : 1;
		UINT32    ProcessorCx8 : 1;
		UINT32    ProcessorApic : 1;
		UINT32    ProcessorReserved1 : 1;
		UINT32    ProcessorSep : 1;
		UINT32    ProcessorMtrr : 1;
		UINT32    ProcessorPge : 1;
		UINT32    ProcessorMca : 1;
		UINT32    ProcessorCmov : 1;
		UINT32    ProcessorPat : 1;
		UINT32    ProcessorPse36 : 1;
		UINT32    ProcessorPsn : 1;
		UINT32    ProcessorClfsh : 1;
		UINT32    ProcessorReserved2 : 1;
		UINT32    ProcessorDs : 1;
		UINT32    ProcessorAcpi : 1;
		UINT32    ProcessorMmx : 1;
		UINT32    ProcessorFxsr : 1;
		UINT32    ProcessorSse : 1;
		UINT32    ProcessorSse2 : 1;
		UINT32    ProcessorSs : 1;
		UINT32    ProcessorReserved3 : 1;
		UINT32    ProcessorTm : 1;
		UINT32    ProcessorReserved4 : 2;
	} PROCESSOR_FEATURE_FLAGS;
	typedef struct {
		PROCESSOR_SIGNATURE        Signature;
		PROCESSOR_FEATURE_FLAGS    FeatureFlags;
	} PROCESSOR_ID_DATA;

	//32
	/*typedef struct {
		UINT8   AnchorString[4];
		UINT8   EntryPointStructureChecksum;
		UINT8   EntryPointLength;
		UINT8   MajorVersion;
		UINT8   MinorVersion;
		UINT16  MaxStructureSize;
		UINT8   EntryPointRevision;
		UINT8   FormattedArea[5];
		UINT8   IntermediateAnchorString[5];
		UINT8   IntermediateChecksum;
		UINT16  TableLength;
		UINT32  TableAddress;
		UINT16  NumberOfSmbiosStructures;
		UINT8   SmbiosBcdRevision;
	} SMBIOS_STRUCTURE_TABLE;*/

	//64
	typedef struct {
		UINT8     AnchorString[5];
		UINT8     EntryPointStructureChecksum;
		UINT8     EntryPointLength;
		UINT8     MajorVersion;
		UINT8     MinorVersion;
		UINT8     DocRev;
		UINT8     EntryPointRevision;
		UINT8     Reserved;
		UINT32    TableMaximumSize;
		UINT64    TableAddress;
	} SMBIOS_STRUCTURE_TABLE;

	struct _SMBIOS_TYPE4 {
		SMBIOS_HEADER    Hdr; //bios
		SMBIOS_STRING    SocketDesignation;
		UINT8                  ProcessorType;         ///< The enumeration value from PROCESSOR_TYPE_DATA.
		UINT8                  ProcessorFamily;       ///< The enumeration value from PROCESSOR_FAMILY_DATA.
		SMBIOS_STRING    ProcessorManufacturer;
		unsigned long long      ProcessorId;         //fix bios
		SMBIOS_STRING    ProcessorVersion;
		PROCESSOR_VOLTAGE      Voltage;
		UINT16                 ExternalClock;
		UINT16                 MaxSpeed;
		UINT16                 CurrentSpeed;
		UINT8                  Status;
		UINT8                  ProcessorUpgrade;     ///< The enumeration value from PROCESSOR_UPGRADE.
		UINT16                 L1CacheHandle;
		UINT16                 L2CacheHandle;
		UINT16                 L3CacheHandle;
		SMBIOS_STRING    SerialNumber;
		SMBIOS_STRING    AssetTag;
		SMBIOS_STRING    PartNumber;
		UINT8                  CoreCount;
		UINT8                  EnabledCoreCount;
		UINT8                  ThreadCount;
		UINT16                 ProcessorCharacteristics;
		UINT16                 ProcessorFamily2;
		UINT16                 CoreCount2;
		UINT16                 EnabledCoreCount2;
		UINT16                 ThreadCount2;
		UINT16                 ThreadEnabled;
	} SMBIOS_TYPE4,*PSMBIOS_TYPE4;

	/*typedef struct {
		ULONGLONG		  dummy1;
		ULONGLONG		  dummy2;
		ULONGLONG		  dummy3;
		ULONGLONG		  dummy4;
		SMBIOS_STRING     SerialNumber;
	} _SMBIOS_TYPE4;*/

	///
/// Memory Device - Type Detail
///
	typedef struct {
		UINT16    Reserved : 1;
		UINT16    Other : 1;
		UINT16    Unknown : 1;
		UINT16    FastPaged : 1;
		UINT16    StaticColumn : 1;
		UINT16    PseudoStatic : 1;
		UINT16    Rambus : 1;
		UINT16    Synchronous : 1;
		UINT16    Cmos : 1;
		UINT16    Edo : 1;
		UINT16    WindowDram : 1;
		UINT16    CacheDram : 1;
		UINT16    Nonvolatile : 1;
		UINT16    Registered : 1;
		UINT16    Unbuffered : 1;
		UINT16    LrDimm : 1;
	} MEMORY_DEVICE_TYPE_DETAIL;

	//来自edk2
	typedef struct {
		SMBIOS_HEADER                           Hdr;
		UINT16                                     MemoryArrayHandle;
		UINT16                                     MemoryErrorInformationHandle;
		UINT16                                     TotalWidth;
		UINT16                                     DataWidth;
		UINT16                                     Size;
		UINT8                                      FormFactor;        ///< The enumeration value from MEMORY_FORM_FACTOR.
		UINT8                                      DeviceSet;
		SMBIOS_STRING                        DeviceLocator;
		SMBIOS_STRING                        BankLocator;
		UINT8                                      MemoryType;        ///< The enumeration value from MEMORY_DEVICE_TYPE.
		MEMORY_DEVICE_TYPE_DETAIL                  TypeDetail;
		UINT16                                     Speed;
		SMBIOS_STRING                        Manufacturer;
		SMBIOS_STRING                        SerialNumber;
		SMBIOS_STRING                        AssetTag;
		SMBIOS_STRING                        PartNumber;
	} MEMORY_DEVICE_HEADER;

	typedef enum _SYSTEM_INFORMATION_CLASS {
		SystemBasicInformation,
		SystemProcessorInformation,             // obsolete...delete
		SystemPerformanceInformation,
		SystemTimeOfDayInformation,
		SystemPathInformation,
		SystemProcessInformation,
		SystemCallCountInformation,
		SystemDeviceInformation,
		SystemProcessorPerformanceInformation,
		SystemFlagsInformation,
		SystemCallTimeInformation,
		SystemModuleInformation,
		SystemLocksInformation,
		SystemStackTraceInformation,
		SystemPagedPoolInformation,
		SystemNonPagedPoolInformation,
		SystemHandleInformation,
		SystemObjectInformation,
		SystemPageFileInformation,
		SystemVdmInstemulInformation,
		SystemVdmBopInformation,
		SystemFileCacheInformation,
		SystemPoolTagInformation,
		SystemInterruptInformation,
		SystemDpcBehaviorInformation,
		SystemFullMemoryInformation,
		SystemLoadGdiDriverInformation,
		SystemUnloadGdiDriverInformation,
		SystemTimeAdjustmentInformation,
		SystemSummaryMemoryInformation,
		SystemMirrorMemoryInformation,
		SystemPerformanceTraceInformation,
		SystemObsolete0,
		SystemExceptionInformation,
		SystemCrashDumpStateInformation,
		SystemKernelDebuggerInformation,
		SystemContextSwitchInformation,
		SystemRegistryQuotaInformation,
		SystemExtendServiceTableInformation,
		SystemPrioritySeperation,
		SystemVerifierAddDriverInformation,
		SystemVerifierRemoveDriverInformation,
		SystemProcessorIdleInformation,
		SystemLegacyDriverInformation,
		SystemCurrentTimeZoneInformation,
		SystemLookasideInformation,
		SystemTimeSlipNotification,
		SystemSessionCreate,
		SystemSessionDetach,
		SystemSessionInformation,
		SystemRangeStartInformation,
		SystemVerifierInformation,
		SystemVerifierThunkExtend,
		SystemSessionProcessInformation,
		SystemLoadGdiDriverInSystemSpace,
		SystemNumaProcessorMap,
		SystemPrefetcherInformation,
		SystemExtendedProcessInformation,
		SystemRecommendedSharedDataAlignment,
		SystemComPlusPackage,
		SystemNumaAvailableMemory,
		SystemProcessorPowerInformation,
		SystemEmulationBasicInformation,
		SystemEmulationProcessorInformation,
		SystemExtendedHandleInformation,
		SystemLostDelayedWriteInformation,
		SystemBigPoolInformation,
		SystemSessionPoolTagInformation,
		SystemSessionMappedViewInformation,
		SystemHotpatchInformation,
		SystemObjectSecurityMode,
		SystemWatchdogTimerHandler,
		SystemWatchdogTimerInformation,
		SystemLogicalProcessorInformation,
		SystemWow64SharedInformation,
		SystemRegisterFirmwareTableInformationHandler,
		SystemFirmwareTableInformation,
		SystemModuleInformationEx,
		SystemVerifierTriageInformation,
		SystemSuperfetchInformation,
		SystemMemoryListInformation,
		SystemFileCacheInformationEx,
		MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
	} SYSTEM_INFORMATION_CLASS;
#pragma pack()

    //
	typedef NTSTATUS(__cdecl* PFNFTH) (IN OUT PSYSTEM_FIRMWARE_TABLE_INFORMATION SystemFirmwareTableInfo);

	typedef struct _SYSTEM_FIRMWARE_TABLE_HANDLER {
		ULONG       ProviderSignature;
		BOOLEAN     Register;
		PFNFTH      FirmwareTableHandler;
		PVOID       DriverObject;
	} SYSTEM_FIRMWARE_TABLE_HANDLER, * PSYSTEM_FIRMWARE_TABLE_HANDLER;

	typedef struct _SYSTEM_FIRMWARE_TABLE_HANDLER_NODE {
		SYSTEM_FIRMWARE_TABLE_HANDLER SystemFWHandler;
		LIST_ENTRY FirmwareTableProviderList;
	} SYSTEM_FIRMWARE_TABLE_HANDLER_NODE, * PSYSTEM_FIRMWARE_TABLE_HANDLER_NODE;

	typedef NTSTATUS(*ZWSETSYSTEMINFORMATION)
		(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
			IN OUT PVOID SystemInformation, 
			IN ULONG SystemInformationLength);
	ZWSETSYSTEMINFORMATION funZwSetSystemInfomation;

	DWORD swap_bytes4(DWORD value)
	{
		return ((value >> 24) & 0xFF) |      // Move byte 3 to byte 0
			((value << 8) & 0xFF0000) |   // Move byte 1 to byte 2
			((value >> 8) & 0xFF00) |     // Move byte 2 to byte 1
			((value << 24) & 0xFF000000); // Move byte 0 to byte 3
	}

	unsigned short swap_bytes2(unsigned short value)
	{
		int a = (value & 0x00FF) << 8;
		int b = (value & 0xFF00) >> 8;

		return (value & 0x00FF) << 8
		| (value & 0xFF00) >> 8;
	}

	unsigned short transform(DWORD64 value) {
		return (short)(value >> 48);
	}

	char* get_smbios_string(SMBIOS_HEADER* header, SMBIOS_STRING str)
	{
		if (header == 0 || str == 0) return 0;

		const char* start = reinterpret_cast<char*>(header) + header->Length;
		//if (*start == 0) return 0;

		while (--str) start += strlen(start) + 1;
		//start += 4;

		return const_cast<char*>(start);
	}

	/*static WCHAR* get_smbios_string(BYTE id, const char* buf, UINT offset, UINT buflen)
	{
		const char* ptr = buf + offset;
		UINT i = 0;

		if (!id || offset >= buflen) return NULL;
		for (ptr = buf + offset; ptr - buf < buflen && *ptr; ptr++)
		{
			if (++i == id) return heap_strdupAW(ptr);
			for (; ptr - buf < buflen; ptr++) if (!*ptr) break;
		}
		return NULL;
	}*/

	void stringToHex(const char* str, char* hexStr, int nLen) {

		//int nLen = (int)strlen(str);

		int nLoop = 0;
		while (MmIsAddressValid((PVOID)str)
			&& MmIsAddressValid((PVOID)(str + 1))
			&& !(*str == '\0' && *(++str) == '\0')) {
			sprintf(hexStr, "%s%02X ", hexStr, (unsigned char)*str);
			str++;
			hexStr += 3; // 移动到下一个位置，留出空格的位置
			//hexStr += 2;

			if (nLoop >= 200 || nLoop == nLen)
			{
				DbgPrint("nLoop>=200 or nLoop== nLen\r\n");
				break;
			}
			nLoop++;
		}
	}

	void PrintfHexString(BYTE* pbData, int nLen)
	{
		int nLine = nLen / 16;
		int nRemainder = nLen % 16;

		for (int j = 0; j < nLine; j++)
		{
			//显示16进制数据
			for (int i = j * 16; i < 16 + j * 16; i++)
			{
				DbgPrint("%02x ", pbData[i]);
			}
			DbgPrint("| ");

			//显示可显数据到
			for (int i = j * 16; i < 16 + j * 16; i++)
			{
				DbgPrint("%c", isprint(pbData[i]) ? pbData[i] : '.');
			}
			DbgPrint("\r\n");
		}

		//打印剩余的数据
		for (int i = 0; i < nRemainder; i++)
		{
			DbgPrint("%02x ", pbData[i]);
		}
		DbgPrint("| ");

		for (int i = 0; i < nRemainder; i++)
		{
			DbgPrint("%c", isprint(pbData[i]) ? pbData[i] : '.');
		}

		DbgPrint(" |");
		DbgPrint("\n");
	}

	void RandomizeSerialNumber(char* str, int length)
	{
#define CHARSET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define CHARSET_SIZE (sizeof(CHARSET) - 1)

		LARGE_INTEGER seed;
		KeQuerySystemTime(&seed);
		ULONG randSeed = (ULONG)(seed.QuadPart & 0xFFFFFFFF);

		for (int i = 0; i < length; i++) {
			randSeed = RtlRandomEx(&randSeed);
			str[i] = CHARSET[randSeed % CHARSET_SIZE];
		}
		str[length] = '\0'; // 添加字符串结束符
	}

	void process_smbios_table(SMBIOS_HEADER* header)
	{
		auto TableLength = [](PSMBIOS_HEADER pHeader) -> size_t
		{
			char* current = reinterpret_cast<char*>(pHeader) + pHeader->Length;
			size_t i = 1;

			for (i; current[i - 1] != '\0' || current[i] != '\0'; i++)
			{
				// Scan until we find a double zero byte
			}

			return pHeader->Length + i + 1;
		};

		auto GetString = [](PSMBIOS_HEADER pHeader, unsigned char id, int nLen) -> char*
		{
			UNREFERENCED_PARAMETER(nLen);

			char* string = reinterpret_cast<char*>(pHeader) + pHeader->Length;

			char hexOutput[256] = { 0 };
			//stringToHex(string, hexOutput, nLen);

			//DbgPrint("%s\r\n", hexOutput);

			for (DWORD i = 1; i < id; i++)
			{
				string += strlen(string) + 1;
			}

			return string;
		};

		{
			char* serialNumber = NULL, * Uuid = NULL, * ProcessorManufacturer = NULL;

			PrintfHexString((BYTE*)header, header->Length);

			if (header->Type == 1) //主板bios
			{
				SMBIOS_TYPE1* pSystemInfoHeader = reinterpret_cast<SMBIOS_TYPE1*>(header);

				serialNumber = GetString((SMBIOS_HEADER*)pSystemInfoHeader, pSystemInfoHeader->SerialNumber,
					header->Length);

				DbgPrint("read SystemInfo: serialNumber:%s\r\n", serialNumber);
			}
			else if (header->Type == 2) //主板物理序列号
			{
				SMBIOS_TYPE3* pBaseBoardHeader = reinterpret_cast<SMBIOS_TYPE3*>(header);

				serialNumber = GetString((SMBIOS_HEADER*)pBaseBoardHeader, pBaseBoardHeader->SerialNumber,
					header->Length);
				DbgPrint("read BaseBoard: %s\r\n", serialNumber);
			}
			else if (header->Type == 4) // CPU
			{
				_SMBIOS_TYPE4* pCpuHeader = reinterpret_cast<_SMBIOS_TYPE4*>(header);

				serialNumber = GetString((SMBIOS_HEADER*)pCpuHeader, pCpuHeader->SerialNumber,
					header->Length);

				ProcessorManufacturer = GetString((SMBIOS_HEADER*)pCpuHeader,
						pCpuHeader->ProcessorManufacturer,
						header->Length);
				if (pCpuHeader->ProcessorType & 3) //CPU
				{
					DbgPrint("read CPU: serialNumber:%s.ProcessorManufacturer:%s.Len:%d\r\n", serialNumber,
						ProcessorManufacturer, header->Length);
				}
				else if (pCpuHeader->ProcessorType & 6) //Video
				{
					DbgPrint("read Video: serialNumber:%s.ProcessorManufacturer:%s.Len:%d\r\n", serialNumber,
						ProcessorManufacturer, header->Length);
				}
			}
			else if (header->Type == 17) // MemoryDevice
			{
				MEMORY_DEVICE_HEADER *pMemoryDeviceHeader = reinterpret_cast<MEMORY_DEVICE_HEADER*>(header);

				serialNumber = GetString((SMBIOS_HEADER*)pMemoryDeviceHeader, pMemoryDeviceHeader->SerialNumber,
					header->Length);
				DbgPrint("read MemoryDevice: %s\r\n", serialNumber);
			}

			if (serialNumber)
			{
				if (header->Type == 1) // SystemInfo 主板bios
				{
					SMBIOS_TYPE1* pSystemInfoHeader = reinterpret_cast<SMBIOS_TYPE1*>(header);

					RandomizeSerialNumber(serialNumber, 12);
					DbgPrint("write: %s\r\n", serialNumber);

					serialNumber = GetString((SMBIOS_HEADER*)pSystemInfoHeader, pSystemInfoHeader->SerialNumber,
						header->Length);
					DbgPrint("re-read BaseBoard bios: %s.Len:%d\r\n", serialNumber, header->Length);

					memset(&pSystemInfoHeader->Uuid, 0, sizeof(pSystemInfoHeader->Uuid));
				}
				else if (header->Type == 2) // BaseBoard Physical SN
				{
					SMBIOS_TYPE3* pBaseBoardHeader = reinterpret_cast<SMBIOS_TYPE3*>(header);

					RandomizeSerialNumber(serialNumber, 12);
					DbgPrint("write: %s\r\n", serialNumber);

					serialNumber = GetString((SMBIOS_HEADER*)pBaseBoardHeader, pBaseBoardHeader->SerialNumber,
						header->Length);
					DbgPrint("re-read BaseBoard: %s.Len:%d\r\n", serialNumber, header->Length);
				}
				else if (header->Type == 4) // CPU
				{
					_SMBIOS_TYPE4* pCpuHeader = reinterpret_cast<_SMBIOS_TYPE4*>(header);

					RandomizeSerialNumber(serialNumber, 12);
					DbgPrint("write: %s\r\n", serialNumber);

					serialNumber = GetString((SMBIOS_HEADER*)pCpuHeader, pCpuHeader->SerialNumber,
						header->Length);

					ProcessorManufacturer = GetString((SMBIOS_HEADER*)pCpuHeader,
						pCpuHeader->ProcessorManufacturer,
						header->Length);
					if (pCpuHeader->ProcessorType & 3) //CPU
					{
						DbgPrint("re-read CPU: serialNumber:%s.ProcessorManufacturer:%s.Len:%d\r\n", serialNumber,
							ProcessorManufacturer, header->Length);
					}
					else if (pCpuHeader->ProcessorType & 6) //Video
					{
						DbgPrint("re-read Video: serialNumber:%s.ProcessorManufacturer:%s.Len:%d\r\n", serialNumber,
							ProcessorManufacturer, header->Length);
					}
				}
				else if (header->Type == 17) // MemoryDevice
				{
					RandomizeSerialNumber(serialNumber, 12);
					DbgPrint("write: %s\r\n", serialNumber);

					MEMORY_DEVICE_HEADER *pMemoryDeviceHeader = reinterpret_cast<MEMORY_DEVICE_HEADER*>(header);

					serialNumber = GetString((SMBIOS_HEADER*)pMemoryDeviceHeader, pMemoryDeviceHeader->SerialNumber,
						header->Length);
					DbgPrint("re-read MemoryDevice: %s\r\n", serialNumber);
				}
			}

			header = (PSMBIOS_HEADER)((char*)header + TableLength(header));
		}

		DbgPrint("[WmipRawSMBiosTableHandlerHook] Serial numbers spoofed.");
	}

	void handle_smbios_table(void* mapped, unsigned long length)
	{
		char* end_address = static_cast<char*>(mapped) + length;

		while (true)
		{
			SMBIOS_HEADER* header = static_cast<SMBIOS_HEADER*>(mapped);
			if (header->Type == 127 && header->Length == 4)
				break;

			process_smbios_table(header);

			char* ptr = static_cast<char*>(mapped) + header->Length;
			while (0 != (*ptr | *(ptr + 1))) ptr++;
			ptr += 2;
			if (ptr >= end_address)
				break;

			mapped = ptr;
		}
	}
	
	//bool spoofer_smbios1()
	//{
	//	DWORD64 address = 0;
	//	DWORD32 size = 0;
	//	if (n_util::get_module_base_address("ntoskrnl.exe", address, size) == false) return false;
	//	n_log::printf("ntoskrnl address : %llx \t size : %x \n", address, size);

	//	// WmipFindSMBiosStructure -> WmipSMBiosTablePhysicalAddress
	//	PPHYSICAL_ADDRESS physical_address = (PPHYSICAL_ADDRESS)n_util::find_pattern_image(address,
	//		"\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15",
	//		"xxx????xxxx?xx");
	//	if (physical_address == 0) return false;

	//	physical_address = reinterpret_cast<PPHYSICAL_ADDRESS>(reinterpret_cast<char*>(physical_address) 
	//		+ 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(physical_address) + 3));
	//	if (physical_address == 0) return false;
	//	n_log::printf("physical address : %llx \n", physical_address);
	//	
	//	// WmipFindSMBiosStructure -> WmipSMBiosTableLength
	//	DWORD64 physical_length_address = n_util::find_pattern_image(address,
	//		/*"\x8B\x1D\x00\x00\x00\x00\x48\x8B\xD0\x44\x8B\xC3\x48\x8B\xCD\xE8\x00\x00\x00\x00\x8B\xD3\x48\x8B"*/

	//	  /*PAGE : 00000001408F0329 48 8B 0D F0 CD 0B 00          mov     rcx, cs:WmipSMBiosTablePhysicalAddress
	//		PAGE : 00000001408F0330 48 85 C9                      test    rcx, rcx
	//		PAGE : 00000001408F0333 74 2C                         jz      short loc_1408F0361
	//		PAGE : 00000001408F0333
	//		PAGE : 00000001408F0335 8B 15 19 CD 0B 00             mov     edx, cs:WmipSMBiosTableLength
	//		PAGE : 00000001408F033B 44 8D 43 04                   lea     r8d, [rbx + 4]
	//		PAGE:00000001408F033F E8 BC 69 80 FF                call    MmMapIoSpaceEx*/
	//		"\x48\x8B\x00\x00\x00\x00\x00\x48\x85\x00\x74\x00\x8B\x00\x00\x00\x00\x00\x44\x00\x00\x00\xE8",
	//		"xx?????xx?x?x?????x???x");
	//	if (physical_length_address == 0) return false;
	//	DWORD dwTemp = ((*(unsigned long*)(physical_length_address + 14)));
	//	ULONG_PTR physical_length = *(ULONG_PTR*)(physical_length_address + 12 +
	//		dwTemp);
	//	physical_length = transform(physical_length);

	//	if (physical_length == 0) return false;
	//	n_log::printf("physical length : %d \n", physical_length);

	//	void* mapped = MmMapIoSpace(*physical_address, physical_length, MmNonCached);
	//	if (mapped == 0) return false;

	//	handle_smbios_table(mapped, physical_length);

	//	MmUnmapIoSpace(mapped, physical_length);

	//	return true;
	//}

	bool spoofer_smbios()
	{
		DWORD64 address = 0;
		DWORD32 size = 0;
		if (n_util::get_module_base_address("ntoskrnl.exe", address, size) == false) return false;
		n_log::printf("ntoskrnl address : %llx \t size : %x \n", address, size);

		// WmipFindSMBiosStructure -> WmipSMBiosTablePhysicalAddress
		PPHYSICAL_ADDRESS physical_address = (PPHYSICAL_ADDRESS)n_util::find_pattern_image(address,
			"\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15",
			"xxx????xxxx?xx");
		if (physical_address == 0) return false;

		physical_address = reinterpret_cast<PPHYSICAL_ADDRESS>(reinterpret_cast<char*>(physical_address) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(physical_address) + 3));
		if (physical_address == 0) return false;
		n_log::printf("physical address : %llx \n", physical_address);

		// WmipFindSMBiosStructure -> WmipSMBiosTableLength
		DWORD64 physical_length_address = n_util::find_pattern_image(address,
			"\x8B\x1D\x00\x00\x00\x00\x48\x8B\xD0\x44\x8B\xC3\x48\x8B\xCD\xE8\x00\x00\x00\x00\x8B\xD3\x48\x8B",
			"xx????xxxxxxxxxx????xxxx");
		if (physical_length_address == 0) return false;

		unsigned long physical_length = *reinterpret_cast<unsigned long*>(static_cast<char*>((void*)physical_length_address) + 6 + *reinterpret_cast<int*>(static_cast<char*>((void*)physical_length_address) + 2));
		if (physical_length == 0) return false;
		n_log::printf("physical length : %d \n", physical_length);

		void* mapped = MmMapIoSpace(*physical_address, physical_length, MmNonCached);
		if (mapped == 0) return false;

		handle_smbios_table(mapped, physical_length);

		MmUnmapIoSpace(mapped, physical_length);

		return true;
	}

	NTSTATUS
		/*__cdecl*/
		WmipRawSMBiosTableHandler1(
			PSYSTEM_FIRMWARE_TABLE_INFORMATION TableInfo
		)
	{
		UNREFERENCED_PARAMETER(TableInfo);

		return STATUS_SUCCESS;
	}

	VOID WmipRegisterFirmwareProviders()
	{
		SYSTEM_FIRMWARE_TABLE_HANDLER   TableHandler;
		NTSTATUS ntStatus;
		PUCHAR pPrevMode = NULL;
		UCHAR prevMode;

		//UNICODE_STRING uniNtNameString;
		//RtlInitUnicodeString(&uniNtNameString, L"\\Driver\\PnpManager"); //Pnp
		//ntStatus = ObReferenceObjectByName( //STATUS_OBJECT_TYPE_MISMATCH
		//	&uniNtNameString,
		//	OBJ_CASE_INSENSITIVE,
		//	NULL,
		//	0,
		//	IoDriverObjectType,
		//	KernelMode,
		//	NULL,
		//	(PVOID*)&g_PnpDriverObject
		//);
		//// 如果失败了就直接返回
		//if (!NT_SUCCESS(ntStatus))
		//{
		//	KdPrint(("Couldn't get the MyTest Device Object\n"));
		//	return;
		//}
		//else
		//	ObDereferenceObject(g_PnpDriverObject);

		funZwSetSystemInfomation = (ZWSETSYSTEMINFORMATION)GetSSDTFunction("ZwSetSystemInformation");
		if (!funZwSetSystemInfomation)
			return;
	
		PETHREAD pEthread = PsGetCurrentThread();
		pPrevMode = (PUCHAR)pEthread + /*g_nPrev_mode_offset*/0x232; //
		prevMode = *pPrevMode;
		*pPrevMode = KernelMode;//内核模式

		// Register the SMBIOS raw provider.
		TableHandler.ProviderSignature = 'RSMB';    // (Raw SMBIOS)
		TableHandler.Register = FALSE;
		TableHandler.FirmwareTableHandler = &WmipRawSMBiosTableHandler1;
		TableHandler.DriverObject = g_PnpDriverObject/*IoPnpDriverObject*/; //这个对象要是IoPnpDriverObject
		ntStatus = funZwSetSystemInfomation(SystemRegisterFirmwareTableInformationHandler,
			(PVOID)&TableHandler, sizeof(SYSTEM_FIRMWARE_TABLE_HANDLER));

		TableHandler.ProviderSignature = 'RSMB';    // (Raw SMBIOS)
		TableHandler.Register = TRUE;
		TableHandler.FirmwareTableHandler = &WmipRawSMBiosTableHandler1;
		TableHandler.DriverObject = g_PnpDriverObject;
		ntStatus = funZwSetSystemInfomation(SystemRegisterFirmwareTableInformationHandler,
			(PVOID)&TableHandler, sizeof(SYSTEM_FIRMWARE_TABLE_HANDLER));

		//恢复之前的线程模式
		*pPrevMode = prevMode;
		
		//// Register the Firmware provider.
		//TableHandler.ProviderSignature = 'FIRM';    // (Firmware)
		//TableHandler.Register = TRUE;
		//TableHandler.FirmwareTableHandler = &WmipFirmwareTableHandler;
		//TableHandler.DriverObject = IoPnpDriverObject;
		//NtSetSystemInformation(SystemRegisterFirmwareTableInformationHandler, (PVOID)&TableHandler, sizeof(SYSTEM_FIRMWARE_TABLE_HANDLER));
	}

	void spoofer_smbios_new()
	{
		WmipRegisterFirmwareProviders();
	}
}