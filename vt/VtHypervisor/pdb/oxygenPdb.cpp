#include "base.h"

#include "oxygenPdb.h"

#include <memory>
#include <string>
#include <utility>

#include "kquery_pdb.h"

#pragma code_seg(".vm")


oxygenPdb::Pdber::Pdber(std::string moduleName)
	: moduleName(std::move(moduleName))
{

	 const auto item = findModule(moduleName);



	 this->base = item.first;
	 this->size = item.second;


	 if (!base)
		 LOG_DEBUG(_XOR_("Find module %s failed!\n"),moduleName.c_str());
}

bool oxygenPdb::Pdber::init()
{
	
	//old
	kqpdb::set_default_server(_XOR_("http://127.0.0.1:9090/"));


	std::string string = _XOR_("\\SystemRoot\\System32\\");
	kqpdb pdb(string + moduleName);
	this->pdb = std::move(pdb);
	
	return true;
}

oxygenPdb::Pdber::~Pdber()
{
}

ULONG_PTR oxygenPdb::Pdber::GetPointer(const char* name)
{
	int64_t offset = 0;
	try {
		offset = pdb.get_symbol(name);
	} catch (...) {
		LOG_DEBUG(_XOR_("[OxygenPdb] GetPointer(%s) threw, returning 0\n"), name);
		return 0;
	}
	return base + offset;
}

size_t oxygenPdb::Pdber::GetOffset(const char* structName, const char* propertyName)
{
	try {
		auto field = pdb.get_struct(structName, propertyName);
		return field.offset;
	} catch (...) {
		LOG_DEBUG(_XOR_("[OxygenPdb] GetOffset(%s,%s) threw, returning 0\n"),
			structName, propertyName);
		return 0;
	}
}

extern "C"
NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation
(
	IN oxygenPdb::SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);





std::pair<oxygenPdb::ptr_t, ULONG> oxygenPdb::Pdber::findModule(std::string moduleName)
{

	ULONG moduleInfoSize{};
	ZwQuerySystemInformation(SystemModuleInformation, 0, moduleInfoSize, &moduleInfoSize);

	const auto buffer = std::make_unique<char[]>(moduleInfoSize + 1000);
	if (!buffer)
		return {};

	if (!NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, buffer.get(), moduleInfoSize, &moduleInfoSize)))
		return {};

	const auto mods = reinterpret_cast<RTL_PROCESS_MODULES*>(buffer.get());
	for (size_t i{}; i < mods->NumberOfModules; ++i)
	{
		std::string tmpPathName{ reinterpret_cast<char*>(&mods->Modules[i].FullPathName[0]) };
		std::string pathName{ tmpPathName.begin(), tmpPathName.end() };
		if (pathName.find(moduleName) != std::string::npos)
			return { (ptr_t)mods->Modules[i].ImageBase,mods->Modules[i].ImageSize };
	}

	return { 0,0 };//no find

}




