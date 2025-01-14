﻿#include "ssdt.h"
#include "undocumented.h"
#include "pe.h"

#include "ntdll.h"

//structures
struct SSDTStruct
{
	LONG* pServiceTable;
	PVOID pCounterTable;
#ifdef _WIN64
	ULONGLONG NumberOfServices;
#else
	ULONG NumberOfServices;
#endif
	PCHAR pArgumentTable;
};

//Based on: https://github.com/hfiref0x/WinObjEx64 
// 获取SSDT表的地址
static SSDTStruct* SSDTfind()
{
	static SSDTStruct* SSDT = 0;
	if (!SSDT)
	{
#ifndef _WIN64
		//x86 code
		// 如果是x86,通过函数 MmGetSystemRoutineAddress 可以获取到 KeServiceDescriptorTable 的地址
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
		SSDT = (SSDTStruct*)MmGetSystemRoutineAddress(&routineName);  // 获取SSDT地址
#else
		// x64 code
		// x64没有 MmGetSystemRoutineAddress 函数,需要通过特征码搜索得到 SSDT 地址
		ULONG kernelSize;
		ULONG_PTR kernelBase = (ULONG_PTR)Undocumented::GetKernelBase(&kernelSize); // 获取内核模块基地址
		if (kernelBase == 0 || kernelSize == 0)
			return NULL;


		/*
		kd> u KiSystemServiceStart l 100
				nt!KiSystemServiceStart:
				fffff800`040eadde 4889a3d8010000  mov     qword ptr [rbx+1D8h],rsp
				fffff800`040eade5 8bf8            mov     edi,eax
				fffff800`040eade7 c1ef07          shr     edi,7
				fffff800`040eadea 83e720          and     edi,20h
				fffff800`040eaded 25ff0f0000      and     eax,0FFFh
				nt!KiSystemServiceRepeat:
				fffff800`040eadf2 4c8d1507bb1f00  lea     r10,[nt!KeServiceDescriptorTable (fffff800`042e6900)]
				fffff800`040eadf9 4c8d1dc0bb1f00  lea     r11,[nt!KeServiceDescriptorTableShadow (fffff800`042e69c0)]
		*/
		// 通过 KiSystemServiceStart 函数特征码 找到该函数,再进一步找到 KeServiceDescriptorTable 地址
		const unsigned char KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
		const ULONG signatureSize = sizeof(KiSystemServiceStartPattern);
		bool found = false;
		ULONG KiSSSOffset; //  记录 KiSystemServiceStart 函数在内核模块中的偏移
		// 遍历内核数据,寻找特征码的位置
		for (KiSSSOffset = 0; KiSSSOffset < kernelSize - signatureSize; KiSSSOffset++)
		{
			unsigned char* address = ((unsigned char*)kernelBase + KiSSSOffset);
			if (MmIsAddressValid(address)) //  Fix Bugs: 这里需要使用 MmIsAddressValid 函数判断 address 是否为有效地址,否则 Win10 19045 运行蓝屏
			{
				if (RtlCompareMemory(address, KiSystemServiceStartPattern, signatureSize) == signatureSize)
				{
					found = true;
					break;
				}
			}

		}
		if (!found)
			return NULL;

		// lea r10, KeServiceDescriptorTable
		ULONG_PTR address = kernelBase + KiSSSOffset + signatureSize;  // KeServiceDescriptorTable地址
		LONG relativeOffset = 0; // 相对偏移
		if ((*(unsigned char*)address == 0x4c) &&
			(*(unsigned char*)(address + 1) == 0x8d) &&
			(*(unsigned char*)(address + 2) == 0x15))
		{
			relativeOffset = *(LONG*)(address + 3);
		}
		if (relativeOffset == 0)
			return NULL;

		SSDT = (SSDTStruct*)(address + relativeOffset + 7); //  本身地址 + 相对偏移 + 7(PS:硬编码的原因)
#endif
	}
	return SSDT;
}


PVOID SSDT::GetFunctionAddress(const char* apiname)
{
	//read address from SSDT
	SSDTStruct* SSDT = SSDTfind();  // 获取SSDT结构
	if (!SSDT)
	{
		DPRINT("[DeugMessage] SSDT not found...\r\n");
		return 0;
	}
	ULONG_PTR SSDTbase = (ULONG_PTR)SSDT->pServiceTable; // SSDT表地址
	if (!SSDTbase)
	{
		DPRINT("[DeugMessage] ServiceTable not found...\r\n");
		return 0;
	}
	ULONG readOffset = NTDLL::GetExportSsdtIndex(apiname); // 通过函数名称获取该函数在SSDT表中的索引                                                                       
	if (readOffset == -1)
		return 0;
	if (readOffset >= SSDT->NumberOfServices)
	{
		DPRINT("[DeugMessage] Invalid read offset...\r\n");
		return 0;
	}
#ifdef _WIN64
	return (PVOID)((SSDT->pServiceTable[readOffset] >> 4) + SSDTbase); // 通过索引 + SSDT表地址  得到函数地址
#else
	return (PVOID)SSDT->pServiceTable[readOffset]; // 通过索引 + SSDT表地址  得到函数地址
#endif
}

static void InterlockedSet(LONG* Destination, LONG Source)
{
	//Change memory properties.
	PMDL g_pmdl = IoAllocateMdl(Destination, sizeof(LONG), 0, 0, NULL);
	if (!g_pmdl)
		return;
	MmBuildMdlForNonPagedPool(g_pmdl);
	LONG* Mapped = (LONG*)MmMapLockedPages(g_pmdl, KernelMode);
	if (!Mapped)
	{
		IoFreeMdl(g_pmdl);
		return;
	}
	InterlockedExchange(Mapped, Source);
	//Restore memory properties.
	MmUnmapLockedPages((PVOID)Mapped, g_pmdl);
	IoFreeMdl(g_pmdl);
}

#ifdef _WIN64
static PVOID FindCaveAddress(PVOID CodeStart, ULONG CodeSize, ULONG CaveSize)
{
	unsigned char* Code = (unsigned char*)CodeStart;

	for (unsigned int i = 0, j = 0; i < CodeSize; i++)
	{
		if (Code[i] == 0x90 || Code[i] == 0xCC)  //NOP or INT3
			j++;
		else
			j = 0;
		if (j == CaveSize)
			return (PVOID)((ULONG_PTR)CodeStart + i - CaveSize + 1);
	}
	return 0;
}
#endif //_WIN64

HOOK SSDT::Hook(const char* apiname, void* newfunc)
{
	SSDTStruct* SSDT = SSDTfind();
	if (!SSDT)
	{
		DPRINT("[DeugMessage] SSDT not found...\r\n");
		return 0;
	}
	ULONG_PTR SSDTbase = (ULONG_PTR)SSDT->pServiceTable;
	if (!SSDTbase)
	{
		DPRINT("[DeugMessage] ServiceTable not found...\r\n");
		return 0;
	}
	int FunctionIndex = NTDLL::GetExportSsdtIndex(apiname);
	if (FunctionIndex == -1)
		return 0;
	if ((ULONGLONG)FunctionIndex >= SSDT->NumberOfServices)
	{
		DPRINT("[DeugMessage] Invalid API offset...\r\n");
		return 0;
	}

	HOOK hHook = 0;
	LONG oldValue = SSDT->pServiceTable[FunctionIndex];
	LONG newValue;

#ifdef _WIN64
	/*
	x64 SSDT Hook;
	1) find API addr
	2) get code page+size
	3) find cave address
	4) hook cave address (using hooklib)
	5) change SSDT value
	*/

	static ULONG CodeSize = 0;
	static PVOID CodeStart = 0;
	if (!CodeStart)
	{
		ULONG_PTR Lowest = SSDTbase;
		ULONG_PTR Highest = Lowest + 0x0FFFFFFF;
		UNREFERENCED_PARAMETER(Highest);
		DPRINT("[DeugMessage] Range: 0x%p-0x%p\r\n", Lowest, Highest);
		CodeSize = 0;
		CodeStart = PE::GetPageBase(Undocumented::GetKernelBase(), &CodeSize, (PVOID)((oldValue >> 4) + SSDTbase));
		if (!CodeStart || !CodeSize)
		{
			DPRINT("[DeugMessage] PeGetPageBase failed...\r\n");
			return 0;
		}
		DPRINT("[DeugMessage] CodeStart: 0x%p, CodeSize: 0x%X\r\n", CodeStart, CodeSize);
		if ((ULONG_PTR)CodeStart < Lowest)  //start of the page is out of range (impossible, but whatever)
		{
			CodeSize -= (ULONG)(Lowest - (ULONG_PTR)CodeStart);
			CodeStart = (PVOID)Lowest;
			DPRINT("[DeugMessage] CodeStart: 0x%p, CodeSize: 0x%X\r\n", CodeStart, CodeSize);
		}
		DPRINT("[DeugMessage] Range: 0x%p-0x%p\r\n", CodeStart, (ULONG_PTR)CodeStart + CodeSize);
	}

	PVOID CaveAddress = FindCaveAddress(CodeStart, CodeSize, sizeof(HOOKOPCODES));
	if (!CaveAddress)
	{
		DPRINT("[DeugMessage] FindCaveAddress failed...\r\n");
		return 0;
	}
	DPRINT("[DeugMessage] CaveAddress: 0x%p\r\n", CaveAddress);

	hHook = Hooklib::Hook(CaveAddress, (void*)newfunc);
	if (!hHook)
		return 0;

	newValue = (LONG)((ULONG_PTR)CaveAddress - SSDTbase);
	newValue = (newValue << 4) | oldValue & 0xF;

	//update HOOK structure
	hHook->SSDTindex = FunctionIndex;
	hHook->SSDTold = oldValue;
	hHook->SSDTnew = newValue;
	hHook->SSDTaddress = (oldValue >> 4) + SSDTbase;

#else
	/*
	x86 SSDT Hook:
	1) change SSDT value
	*/
	newValue = (ULONG)newfunc;

	hHook = (HOOK)RtlAllocateMemory(true, sizeof(HOOKSTRUCT));

	//update HOOK structure
	hHook->SSDTindex = FunctionIndex;
	hHook->SSDTold = oldValue;
	hHook->SSDTnew = newValue;
	hHook->SSDTaddress = oldValue;

#endif

	InterlockedSet(&SSDT->pServiceTable[FunctionIndex], newValue);

	DPRINT("[DeugMessage] SSDThook(%s:0x%p, 0x%p)\r\n", apiname, hHook->SSDTold, hHook->SSDTnew);

	return hHook;
}

void SSDT::Hook(HOOK hHook)
{
	if (!hHook)
		return;
	SSDTStruct* SSDT = SSDTfind();
	if (!SSDT)
	{
		DPRINT("[DeugMessage] SSDT not found...\r\n");
		return;
	}
	LONG* SSDT_Table = SSDT->pServiceTable;
	if (!SSDT_Table)
	{
		DPRINT("[DeugMessage] ServiceTable not found...\r\n");
		return;
	}
	InterlockedSet(&SSDT_Table[hHook->SSDTindex], hHook->SSDTnew);
}

void SSDT::Unhook(HOOK hHook, bool free)
{
	if (!hHook)
		return;
	SSDTStruct* SSDT = SSDTfind();
	if (!SSDT)
	{
		DPRINT("[DeugMessage] SSDT not found...\r\n");
		return;
	}
	LONG* SSDT_Table = SSDT->pServiceTable;
	if (!SSDT_Table)
	{
		DPRINT("[DeugMessage] ServiceTable not found...\r\n");
		return;
	}
	InterlockedSet(&SSDT_Table[hHook->SSDTindex], hHook->SSDTold);
#ifdef _WIN64
	if (free)
		Hooklib::Unhook(hHook, true);
#else
	if (free)
		RtlFreeMemory(hHook);
#endif
	}