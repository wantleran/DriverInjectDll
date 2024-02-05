#include "ntdll.h"

#include "pe.h"

unsigned char* NTDLL::FileData = 0;
ULONG NTDLL::FileSize = 0;


// 读取ntdll.dll的数据至FileData变量
NTSTATUS NTDLL::Initialize()
{
	UNICODE_STRING FileName;
	OBJECT_ATTRIBUTES ObjectAttributes;
	RtlInitUnicodeString(&FileName, L"\\SystemRoot\\system32\\ntdll.dll");
	InitializeObjectAttributes(&ObjectAttributes, &FileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)  // 判断IRQL等级  PASSIVE_LEVEL: 没有被屏蔽的中断
	{
#ifdef _DEBUG
		DPRINT("[DeugMessage] KeGetCurrentIrql != PASSIVE_LEVEL!\n");
#endif
		return STATUS_UNSUCCESSFUL;
	}

	HANDLE FileHandle;
	IO_STATUS_BLOCK IoStatusBlock;
	// 创建ntdll.dll文件的句柄。如果成功，则会返回句柄给FileHandle。
	NTSTATUS NtStatus = ZwCreateFile(&FileHandle,
		GENERIC_READ,
		&ObjectAttributes,
		&IoStatusBlock, NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);

	// 判断是否成功获取ntdll.dll的句柄
	if (NT_SUCCESS(NtStatus))
	{
		FILE_STANDARD_INFORMATION StandardInformation = { 0 };
		// 获取ntdll.dll文件的信息,如:文件大小.
		NtStatus = ZwQueryInformationFile(FileHandle, &IoStatusBlock, &StandardInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);

		// 判断文件信息是否获取成功
		if (NT_SUCCESS(NtStatus))
		{
			// 获取ntdll.dll的大小
			FileSize = StandardInformation.EndOfFile.LowPart;
			DPRINT("[DeugMessage] FileSize of ntdll.dll is %08X!\r\n", StandardInformation.EndOfFile.LowPart);
			// 依据ntdll.dll大小分配内存
			FileData = (unsigned char*)RtlAllocateMemory(true, FileSize);

			LARGE_INTEGER ByteOffset;
			ByteOffset.LowPart = ByteOffset.HighPart = 0;

			// 读取ntdll.dll文件数据至 FileData
			NtStatus = ZwReadFile(FileHandle,
				NULL, NULL, NULL,
				&IoStatusBlock,
				FileData,
				FileSize,
				&ByteOffset, NULL);

			if (!NT_SUCCESS(NtStatus))
			{
				RtlFreeMemory(FileData);
				DPRINT("[DeugMessage] ZwReadFile failed with status %08X...\r\n", NtStatus);
			}
		}
		else
			DPRINT("[DeugMessage] ZwQueryInformationFile failed with status %08X...\r\n", NtStatus);
		ZwClose(FileHandle);
	}
	else
		DPRINT("[DeugMessage] ZwCreateFile failed with status %08X...\r\n", NtStatus);
	return NtStatus;
}


// 释放FileData指针,FileData用来存储ntdll.dll数据
void NTDLL::Deinitialize()
{
	RtlFreeMemory(FileData);
}

int NTDLL::GetExportSsdtIndex(const char* ExportName)
{

	// GetExportOffset 获取目标函数在ntdll.dll的文件偏移FileOffset
	ULONG_PTR ExportOffset = PE::GetExportOffset(FileData, FileSize, ExportName);
	if (ExportOffset == PE_ERROR_VALUE)
		return -1;

	int SsdtOffset = -1;
	unsigned char* ExportData = FileData + ExportOffset; // 获取目标函数的地址

	for (int i = 0; i < 32 && ExportOffset + i < FileSize; i++)
	{
		if (ExportData[i] == 0xC2 || ExportData[i] == 0xC3)  //RET   先遇到retn  函数
			break;
		if (ExportData[i] == 0xB8)  //mov eax,X
		{
			SsdtOffset = *(int*)(ExportData + i + 1); //mov eax,X   这里X是服务号  也就是目标函数在 SSDT表中的索引
			break;
		}
	}

	if (SsdtOffset == -1)
	{
		DPRINT("[DeugMessage] SSDT Offset for %s not found...\r\n", ExportName);
	}


	return SsdtOffset;
}