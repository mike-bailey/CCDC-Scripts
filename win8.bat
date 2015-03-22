REM WIN8 EASY LAUNCH
REM Still a work in progress

REM WIN8 APPS
reg query HKEY_CURRENT_USER\Software\Classes\Extensions\ContractId\Windows.Protocol\PackageId > foundappz.appz
SetLocal EnableDelayedExpansion
set content=
for /F "delims=" %%i in (foundappz.appz) do set content=!content! %%i
set content=%content:HKEY_CURRENT_USER\Software\Classes\Extensions\ContractId\Windows.Protocol\PackageId=%
echo %content% > foundappz.appz
EndLocal
type foundappz.appz
pause
