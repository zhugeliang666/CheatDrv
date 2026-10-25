import os
import uuid

def u():
    return '{' + str(uuid.uuid4()).upper() + '}'

# 1. VtHypervisor
hv_filters = f'''<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup>
    <Filter Include="Core">
      <UniqueIdentifier>{u()}</UniqueIdentifier>
    </Filter>
    <Filter Include="Arch">
      <UniqueIdentifier>{u()}</UniqueIdentifier>
    </Filter>
    <Filter Include="Arch\\Intel">
      <UniqueIdentifier>{u()}</UniqueIdentifier>
    </Filter>
    <Filter Include="Arch\\AMD">
      <UniqueIdentifier>{u()}</UniqueIdentifier>
    </Filter>
    <Filter Include="Hooks">
      <UniqueIdentifier>{u()}</UniqueIdentifier>
    </Filter>
    <Filter Include="Memory">
      <UniqueIdentifier>{u()}</UniqueIdentifier>
    </Filter>
    <Filter Include="Context">
      <UniqueIdentifier>{u()}</UniqueIdentifier>
    </Filter>
    <Filter Include="Diagnostics">
      <UniqueIdentifier>{u()}</UniqueIdentifier>
    </Filter>
    <Filter Include="Common">
      <UniqueIdentifier>{u()}</UniqueIdentifier>
    </Filter>
  </ItemGroup>
  <ItemGroup>
    <ClCompile Include="main.cpp">
      <Filter>Core</Filter>
    </ClCompile>
    <ClCompile Include="vt\\hv.cpp">
      <Filter>Core</Filter>
    </ClCompile>
    <ClCompile Include="vt\\vcpu.cpp">
      <Filter>Core</Filter>
    </ClCompile>
    <ClCompile Include="vt\\vmcs.cpp">
      <Filter>Arch\\Intel</Filter>
    </ClCompile>
    <ClCompile Include="vt\\ept.cpp">
      <Filter>Arch\\Intel</Filter>
    </ClCompile>
    <ClCompile Include="vt\\exit-handlers.cpp">
      <Filter>Arch\\Intel</Filter>
    </ClCompile>
    <ClCompile Include="vt\\hypercalls.cpp">
      <Filter>Arch\\Intel</Filter>
    </ClCompile>
    <ClCompile Include="amd\\svm.cpp">
      <Filter>Arch\\AMD</Filter>
    </ClCompile>
    <ClCompile Include="amd\\svm-exit.cpp">
      <Filter>Arch\\AMD</Filter>
    </ClCompile>
    <ClCompile Include="amd\\npt.cpp">
      <Filter>Arch\\AMD</Filter>
    </ClCompile>
    <ClCompile Include="..\\VtResidentPayload\\hooks\\ept-hook.cpp">
      <Filter>Hooks</Filter>
    </ClCompile>
    <ClCompile Include="..\\VtResidentPayload\\hooks\\ept-probe.cpp">
      <Filter>Hooks</Filter>
    </ClCompile>
    <ClCompile Include="..\\VtResidentPayload\\hooks\\vtcall-hook.cpp">
      <Filter>Hooks</Filter>
    </ClCompile>
    <ClCompile Include="..\\VtResidentPayload\\hooks\\hde64.c">
      <Filter>Hooks</Filter>
    </ClCompile>
    <ClCompile Include="vt\\mm.cpp">
      <Filter>Memory</Filter>
    </ClCompile>
    <ClCompile Include="vt\\page-tables.cpp">
      <Filter>Memory</Filter>
    </ClCompile>
    <ClCompile Include="vt\\mtrr.cpp">
      <Filter>Memory</Filter>
    </ClCompile>
    <ClCompile Include="vt\\gdt.cpp">
      <Filter>Memory</Filter>
    </ClCompile>
    <ClCompile Include="vt\\idt.cpp">
      <Filter>Memory</Filter>
    </ClCompile>
    <ClCompile Include="vt\\segment.cpp">
      <Filter>Memory</Filter>
    </ClCompile>
    <ClCompile Include="poolmanager\\PoolManager.cpp">
      <Filter>Memory</Filter>
    </ClCompile>
    <ClCompile Include="vt\\logger.cpp">
      <Filter>Diagnostics</Filter>
    </ClCompile>
    <ClCompile Include="vt\\timing.cpp">
      <Filter>Diagnostics</Filter>
    </ClCompile>
    <ClCompile Include="vt\\introspection.cpp">
      <Filter>Diagnostics</Filter>
    </ClCompile>
    <ClCompile Include="common\\ntapi.cpp">
      <Filter>Common</Filter>
    </ClCompile>
    <ClCompile Include="common\\symbol_resolver.cpp">
      <Filter>Common</Filter>
    </ClCompile>
    <ClCompile Include="common\\ntutils.cpp">
      <Filter>Common</Filter>
    </ClCompile>
    <ClCompile Include="common\\Utils.cpp">
      <Filter>Common</Filter>
    </ClCompile>
  </ItemGroup>
  <ItemGroup>
    <ClInclude Include="vt\\hv.h">
      <Filter>Core</Filter>
    </ClInclude>
    <ClInclude Include="vt\\vcpu.h">
      <Filter>Core</Filter>
    </ClInclude>
    <ClInclude Include="vt\\vmcs.h">
      <Filter>Arch\\Intel</Filter>
    </ClInclude>
    <ClInclude Include="vt\\ept.h">
      <Filter>Arch\\Intel</Filter>
    </ClInclude>
    <ClInclude Include="vt\\exit-handlers.h">
      <Filter>Arch\\Intel</Filter>
    </ClInclude>
    <ClInclude Include="vt\\hypercalls.h">
      <Filter>Arch\\Intel</Filter>
    </ClInclude>
    <ClInclude Include="vt\\vmx.h">
      <Filter>Arch\\Intel</Filter>
    </ClInclude>
    <ClInclude Include="amd\\svm.h">
      <Filter>Arch\\AMD</Filter>
    </ClInclude>
    <ClInclude Include="amd\\svm-exit.h">
      <Filter>Arch\\AMD</Filter>
    </ClInclude>
    <ClInclude Include="amd\\npt.h">
      <Filter>Arch\\AMD</Filter>
    </ClInclude>
    <ClInclude Include="amd\\vmcb.h">
      <Filter>Arch\\AMD</Filter>
    </ClInclude>
    <ClInclude Include="amd\\amd64.h">
      <Filter>Arch\\AMD</Filter>
    </ClInclude>
    <ClInclude Include="..\\VtResidentPayload\\hooks\\ept-hook.h">
      <Filter>Hooks</Filter>
    </ClInclude>
    <ClInclude Include="..\\VtResidentPayload\\hooks\\ept-probe.h">
      <Filter>Hooks</Filter>
    </ClInclude>
    <ClInclude Include="..\\VtResidentPayload\\hooks\\vtcall-hook.h">
      <Filter>Hooks</Filter>
    </ClInclude>
    <ClInclude Include="..\\VtResidentPayload\\hooks\\hde64.h">
      <Filter>Hooks</Filter>
    </ClInclude>
    <ClInclude Include="..\\VtResidentPayload\\hooks\\table64.h">
      <Filter>Hooks</Filter>
    </ClInclude>
    <ClInclude Include="vt\\mm.h">
      <Filter>Memory</Filter>
    </ClInclude>
    <ClInclude Include="vt\\page-tables.h">
      <Filter>Memory</Filter>
    </ClInclude>
    <ClInclude Include="vt\\mtrr.h">
      <Filter>Memory</Filter>
    </ClInclude>
    <ClInclude Include="vt\\gdt.h">
      <Filter>Memory</Filter>
    </ClInclude>
    <ClInclude Include="vt\\idt.h">
      <Filter>Memory</Filter>
    </ClInclude>
    <ClInclude Include="vt\\segment.h">
      <Filter>Memory</Filter>
    </ClInclude>
    <ClInclude Include="poolmanager\\PoolManager.h">
      <Filter>Memory</Filter>
    </ClInclude>
    <ClInclude Include="vt\\arch.h">
      <Filter>Context</Filter>
    </ClInclude>
    <ClInclude Include="vt\\exception-routines.h">
      <Filter>Context</Filter>
    </ClInclude>
    <ClInclude Include="vt\\interrupt-handlers.h">
      <Filter>Context</Filter>
    </ClInclude>
    <ClInclude Include="vt\\guest-context.h">
      <Filter>Context</Filter>
    </ClInclude>
    <ClInclude Include="vt\\trap-frame.h">
      <Filter>Context</Filter>
    </ClInclude>
    <ClInclude Include="vt\\spin-lock.h">
      <Filter>Context</Filter>
    </ClInclude>
    <ClInclude Include="vt\\logger.h">
      <Filter>Diagnostics</Filter>
    </ClInclude>
    <ClInclude Include="vt\\timing.h">
      <Filter>Diagnostics</Filter>
    </ClInclude>
    <ClInclude Include="vt\\introspection.h">
      <Filter>Diagnostics</Filter>
    </ClInclude>
    <ClInclude Include="vt\\debug-core.h">
      <Filter>Diagnostics</Filter>
    </ClInclude>
    <ClInclude Include="vt\\debug-events.h">
      <Filter>Diagnostics</Filter>
    </ClInclude>
    <ClInclude Include="vt\\debug-watch.h">
      <Filter>Diagnostics</Filter>
    </ClInclude>
    <ClInclude Include="common\\ntutils.h">
      <Filter>Common</Filter>
    </ClInclude>
    <ClInclude Include="common\\symbol_resolver.h">
      <Filter>Common</Filter>
    </ClInclude>
    <ClInclude Include="common\\Utils.h">
      <Filter>Common</Filter>
    </ClInclude>
    <ClInclude Include="base.h">
      <Filter>Common</Filter>
    </ClInclude>
    <ClInclude Include="ia32.hpp">
      <Filter>Common</Filter>
    </ClInclude>
  </ItemGroup>
  <ItemGroup>
    <None Include="vt\\vmx.inl">
      <Filter>Arch\\Intel</Filter>
    </None>
    <None Include="packages.config" />
  </ItemGroup>
  <ItemGroup>
    <MASM Include="vt\\vmx.asm">
      <Filter>Arch\\Intel</Filter>
    </MASM>
    <MASM Include="vt\\vm-exit.asm">
      <Filter>Arch\\Intel</Filter>
    </MASM>
    <MASM Include="vt\\vm-launch.asm">
      <Filter>Arch\\Intel</Filter>
    </MASM>
    <MASM Include="amd\\svm-asm.asm">
      <Filter>Arch\\AMD</Filter>
    </MASM>
    <MASM Include="vt\\arch.asm">
      <Filter>Context</Filter>
    </MASM>
    <MASM Include="vt\\exception-routines.asm">
      <Filter>Context</Filter>
    </MASM>
    <MASM Include="vt\\interrupt-handlers.asm">
      <Filter>Context</Filter>
    </MASM>
  </ItemGroup>
</Project>'''

with open(r'vt\VtHypervisor\VtHypervisor.vcxproj.filters', 'w', encoding='utf-8-sig') as f:
    f.write(hv_filters.replace('\n', '\r\n'))

print('VtHypervisor.vcxproj.filters written successfully')

# 2. VtBootstrapDriver
boot_filters = f'''<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup>
    <Filter Include="Core">
      <UniqueIdentifier>{u()}</UniqueIdentifier>
    </Filter>
    <Filter Include="Common">
      <UniqueIdentifier>{u()}</UniqueIdentifier>
    </Filter>
    <Filter Include="Memory">
      <UniqueIdentifier>{u()}</UniqueIdentifier>
    </Filter>
    <Filter Include="Filer">
      <UniqueIdentifier>{u()}</UniqueIdentifier>
    </Filter>
    <Filter Include="Trace">
      <UniqueIdentifier>{u()}</UniqueIdentifier>
    </Filter>
    <Filter Include="Arch">
      <UniqueIdentifier>{u()}</UniqueIdentifier>
    </Filter>
  </ItemGroup>
  <ItemGroup>
    <ClCompile Include="main.cpp">
      <Filter>Core</Filter>
    </ClCompile>
    <ClCompile Include="Utils.cpp">
      <Filter>Common</Filter>
    </ClCompile>
    <ClCompile Include="common\\ntapi.cpp">
      <Filter>Common</Filter>
    </ClCompile>
    <ClCompile Include="common\\ntutils.cpp">
      <Filter>Common</Filter>
    </ClCompile>
    <ClCompile Include="fake\\filer.cpp">
      <Filter>Filer</Filter>
    </ClCompile>
    <ClCompile Include="poolmanager\\PoolManager.cpp">
      <Filter>Memory</Filter>
    </ClCompile>
  </ItemGroup>
  <ItemGroup>
    <ClInclude Include="base.h">
      <Filter>Common</Filter>
    </ClInclude>
    <ClInclude Include="Utils.h">
      <Filter>Common</Filter>
    </ClInclude>
    <ClInclude Include="common\\ntapi.h">
      <Filter>Common</Filter>
    </ClInclude>
    <ClInclude Include="common\\ntutils.h">
      <Filter>Common</Filter>
    </ClInclude>
    <ClInclude Include="common\\payload_abi.h">
      <Filter>Common</Filter>
    </ClInclude>
    <ClInclude Include="common\\resident_payload.h">
      <Filter>Common</Filter>
    </ClInclude>
    <ClInclude Include="fake\\filer.h">
      <Filter>Filer</Filter>
    </ClInclude>
    <ClInclude Include="fake\\hr.h">
      <Filter>Filer</Filter>
    </ClInclude>
    <ClInclude Include="kli.hpp">
      <Filter>Common</Filter>
    </ClInclude>
    <ClInclude Include="poolmanager\\PoolManager.h">
      <Filter>Memory</Filter>
    </ClInclude>
    <ClInclude Include="trace\\utils.hpp">
      <Filter>Trace</Filter>
    </ClInclude>
    <ClInclude Include="trace\\import.hpp">
      <Filter>Trace</Filter>
    </ClInclude>
    <ClInclude Include="trace\\trace.hpp">
      <Filter>Trace</Filter>
    </ClInclude>
    <ClInclude Include="vt\\hv.h">
      <Filter>Arch</Filter>
    </ClInclude>
  </ItemGroup>
  <ItemGroup>
    <MASM Include="vt\\vmx.asm">
      <Filter>Arch</Filter>
    </MASM>
  </ItemGroup>
  <ItemGroup>
    <None Include="packages.config" />
  </ItemGroup>
</Project>'''

with open(r'vt\VtBootstrapDriver\VtBootstrapDriver.vcxproj.filters', 'w', encoding='utf-8-sig') as f:
    f.write(boot_filters.replace('\n', '\r\n'))

print('VtBootstrapDriver.vcxproj.filters written successfully')
