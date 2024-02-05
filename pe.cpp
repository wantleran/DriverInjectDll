#include "pe.h"


static ULONG RvaToSection(IMAGE_NT_HEADERS* pNtHdr, ULONG dwRVA)
{
	USHORT wSections;
	PIMAGE_SECTION_HEADER pSectionHdr;
	pSectionHdr = IMAGE_FIRST_SECTION(pNtHdr);
	wSections = pNtHdr->FileHeader.NumberOfSections;
	for (int i = 0; i < wSections; i++)
	{
		if (pSectionHdr[i].VirtualAddress <= dwRVA)
			if ((pSectionHdr[i].VirtualAddress + pSectionHdr[i].Misc.VirtualSize) > dwRVA)
			{
				return i;
			}
	}
	return (ULONG)-1;
}

/// <summary>
/// 将相对虚拟地址转换为在文件中的偏移:FileOffset
/// </summary>
/// <param name="pnth">指向NT_HEADER的指针</param>
/// <param name="Rva">相对虚拟地址</param>
/// <param name="FileSize">dll文件的大小</param>
/// <returns></returns>
static ULONG RvaToOffset(PIMAGE_NT_HEADERS pnth, ULONG Rva, ULONG FileSize)
{
	PIMAGE_SECTION_HEADER psh = IMAGE_FIRST_SECTION(pnth); // 获取Section Header的地址
	USHORT NumberOfSections = pnth->FileHeader.NumberOfSections; // 获取section总数
	//遍历所有 section
	for (int i = 0; i < NumberOfSections; i++)
	{
		if (psh->VirtualAddress <= Rva) // 只考虑 在Rva前面的节区
		{
			if ((psh->VirtualAddress + psh->Misc.VirtualSize) > Rva) // 判断 Rva 是否落在这个节区内
			{
				// 在文件中对齐的地址 与 内存中对齐的地址 二者的差值, 可以将 Rva 转换为FileOffset偏移
				Rva -= psh->VirtualAddress; //  psh->VirtualAddress: section在内存中对齐后的相对虚拟地址
				Rva += psh->PointerToRawData; //  psh->PointerToRawData: section在文件中对齐后的相对虚拟地址
				return Rva < FileSize ? Rva : PE_ERROR_VALUE; // 判断 转换后是否大于文件大小
			}
		}
		psh++;// 循环遍历section header
	}
	return PE_ERROR_VALUE;
}

ULONG PE::GetExportOffset(const unsigned char* FileData, ULONG FileSize, const char* ExportName)
{
	//Verify DOS Header  判断是否是DOS头
	PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER)FileData;
	if (pdh->e_magic != IMAGE_DOS_SIGNATURE)
	{
		DPRINT("[DeugMessage] Invalid IMAGE_DOS_SIGNATURE!\r\n");
		return PE_ERROR_VALUE;
	}

	//Verify PE Header 判断是否是PE头
	PIMAGE_NT_HEADERS pnth = (PIMAGE_NT_HEADERS)(FileData + pdh->e_lfanew);
	if (pnth->Signature != IMAGE_NT_SIGNATURE)
	{
		DPRINT("[DeugMessage] Invalid IMAGE_NT_SIGNATURE!\r\n");
		return PE_ERROR_VALUE;
	}

	//Verify Export Directory
	PIMAGE_DATA_DIRECTORY pdd = NULL;
	if (pnth->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) // 判断程序为x64 还是x32
		pdd = ((PIMAGE_NT_HEADERS64)pnth)->OptionalHeader.DataDirectory; // x64数据目录表
	else
		pdd = ((PIMAGE_NT_HEADERS32)pnth)->OptionalHeader.DataDirectory; //x32数据目录表
	// 导出表的相对虚拟地址
	ULONG ExportDirRva = pdd[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	// 导出表的大小
	ULONG ExportDirSize = pdd[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	// 将导出表在内存中的相对虚拟地址转换为在文件中的偏移:FileOffset
	ULONG ExportDirOffset = RvaToOffset(pnth, ExportDirRva, FileSize);
	if (ExportDirOffset == PE_ERROR_VALUE)
	{
		DPRINT("[DeugMessage] Invalid Export Directory!\r\n");
		return PE_ERROR_VALUE;
	}

	//Read Export Directory   // 获取指向Export Directory的指针
	PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)(FileData + ExportDirOffset);
	ULONG NumberOfNames = ExportDir->NumberOfNames; //  以函数名字导出的函数个数
	ULONG AddressOfFunctionsOffset = RvaToOffset(pnth, ExportDir->AddressOfFunctions, FileSize); // 获取导出函数地址表RVA 并转换为FileOffset
	ULONG AddressOfNameOrdinalsOffset = RvaToOffset(pnth, ExportDir->AddressOfNameOrdinals, FileSize); //获取导出函数序号表RVA 并转换为FileOffset
	ULONG AddressOfNamesOffset = RvaToOffset(pnth, ExportDir->AddressOfNames, FileSize); // 导出函数名称表RVA  并转换为FileOffset
	if (AddressOfFunctionsOffset == PE_ERROR_VALUE ||
		AddressOfNameOrdinalsOffset == PE_ERROR_VALUE ||
		AddressOfNamesOffset == PE_ERROR_VALUE)
	{
		DPRINT("[DeugMessage] Invalid Export Directory Contents!\r\n");
		return PE_ERROR_VALUE;
	}
	ULONG* AddressOfFunctions = (ULONG*)(FileData + AddressOfFunctionsOffset); // ntdll.dll 导出函数地址表的地址
	USHORT* AddressOfNameOrdinals = (USHORT*)(FileData + AddressOfNameOrdinalsOffset); // ntdll.dll 导出函数序号表的地址
	ULONG* AddressOfNames = (ULONG*)(FileData + AddressOfNamesOffset); // 导出函数名称表的地址

	//Find Export
	ULONG ExportOffset = PE_ERROR_VALUE;

	// 遍历名称表
	for (ULONG i = 0; i < NumberOfNames; i++)
	{

		// 获取函数名称RVA 并且转换FileOffset
		ULONG CurrentNameOffset = RvaToOffset(pnth, AddressOfNames[i], FileSize);
		if (CurrentNameOffset == PE_ERROR_VALUE)
			continue;
		const char* CurrentName = (const char*)(FileData + CurrentNameOffset); // 通过 FileOffset 得到当前函数的名称

		/*
		AddressOfNames : 指向存储 函数名称 数组的地址
		AddressOfNameOrdinals : 在 AddressOfNames 数组中函数名索引为x的元素  对应的函数序号为 AddressOfNameOrdinals[x]
		AddressOfFunctions	:存储所有导出的函数地址,通过函数序号,得到导出函数的地址

		GetProcAdress()API函数的操作原理:
		1. 对比函数名称,得到在 AddressOfNames 数组中的下标 x
		2. 通过 AddressOfNameOrdinals[x] 得到 函数序号 y
		3. 通过 AddressOfFunctions [y] 得到函数的RVA地址
		*/
		ULONG CurrentFunctionRva = AddressOfFunctions[AddressOfNameOrdinals[i]]; // 获取当前函数的Rva  

		// 判断当前函数的 Rva 是否指向 ExportDirectory 函数导出表内,是则退出跳过该函数
		if (CurrentFunctionRva >= ExportDirRva && CurrentFunctionRva < ExportDirRva + ExportDirSize)
			continue; //we ignore forwarded exports

		// 比较函数名称,判断是否为需要的函数
		if (!strcmp(CurrentName, ExportName))  //compare the export name to the requested export
		{
			ExportOffset = RvaToOffset(pnth, CurrentFunctionRva, FileSize);
			break;
		}
	}

	if (ExportOffset == PE_ERROR_VALUE)
	{
		DPRINT("[DeugMessage] Export %s not found in export table!\r\n", ExportName);
	}

	return ExportOffset;
}

PVOID PE::GetPageBase(PVOID lpHeader, ULONG* Size, PVOID ptr)
{
	if ((unsigned char*)ptr < (unsigned char*)lpHeader)
		return 0;
	ULONG dwRva = (ULONG)((unsigned char*)ptr - (unsigned char*)lpHeader);
	IMAGE_DOS_HEADER* pdh = (IMAGE_DOS_HEADER*)lpHeader;
	if (pdh->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;
	IMAGE_NT_HEADERS* pnth = (IMAGE_NT_HEADERS*)((unsigned char*)lpHeader + pdh->e_lfanew);
	if (pnth->Signature != IMAGE_NT_SIGNATURE)
		return 0;
	IMAGE_SECTION_HEADER* psh = IMAGE_FIRST_SECTION(pnth);
	int section = RvaToSection(pnth, dwRva);
	if (section == -1)
		return 0;
	if (Size)
		*Size = psh[section].SizeOfRawData;
	return (PVOID)((unsigned char*)lpHeader + psh[section].VirtualAddress);
}