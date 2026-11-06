proj_path = r'E:\Project\Drv\MainDrv\Machenike.vcxproj'
with open(proj_path, 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace(
    '<AdditionalDependencies>$(ProjectDir)VMProtectDDK64.lib;',
    '<AdditionalDependencies>$(ProjectDir)VMProtectDDK64.lib;ndis.lib;'
)

with open(proj_path, 'w', encoding='utf-8') as f:
    f.write(text)

print('Added ndis.lib to AdditionalDependencies in Machenike.vcxproj')
