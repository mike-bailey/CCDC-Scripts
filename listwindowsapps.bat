@echo off
color 0f
cls
echo This is a little code to dig the registry for Windows 8 apps...
echo It won't display 100% of them, it's still a bit of a 0-day
reg query HKEY_CURRENT_USER\Software\Classes\Extensions\ContractId\Windows.Protocol\PackageId > foundappz.appz
SetLocal EnableDelayedExpansion
set content=
for /F "delims=" %%i in (foundappz.appz) do set content=!content! %%i
set content=%content:HKEY_CURRENT_USER\Software\Classes\Extensions\ContractId\Windows.Protocol\PackageId=%
echo %content% > foundappz.appz
EndLocal
type foundappz.appz
pause