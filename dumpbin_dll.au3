#NoTrayIcon

EnvSet('PATH', StringFormat('%s\\x64;%s', @ScriptDir, EnvGet('path')))
;~ EnvSet('PATH', StringFormat('%s\\x86;%s', @ScriptDir, EnvGet('path')))

Func msgbox1($a, $b, $c)
	ConsoleWrite(StringFormat('%s, %s\n', $b, $c))
EndFunc   ;==>msgbox1
Global $msgbox = msgbox1
If 0 == @Compiled Then $msgbox = MsgBox
If '1' == EnvGet('debug') Then $msgbox = MsgBox

Local $file = ''
If $CMDLine[0] >= 1 Then $file = $CMDLine[1]
If '' == $file Then $file = FileOpenDialog('select file to dump', @WindowsDir, "All (*.*)", 1)
If Not FileExists($file) Then
	$msgbox(0, 'file not found', $file)
	Exit
EndIf

Local $outputdir = StringRegExp($file, '[^\\/]+$', 1)
$outputdir = $outputdir[0]
If 0 == @Compiled Then $outputdir = StringFormat('v:\\%s', $outputdir)
If $CMDLine[0] >= 2 Then $outputdir = $CMDLine[2]
If 0 == StringInStr($outputdir, ':', 1) Then $outputdir = StringFormat('%s\\%s', @WorkingDir, $outputdir)
DirCreate($outputdir)

ConsoleWrite(StringFormat('input: %s\n', $file))
ConsoleWrite(StringFormat('output: %s\n', $outputdir))

; dumpbin.exe /exports xxx.dll>1.txt
FileChangeDir(@TempDir)
RunWait(StringFormat('cmd.exe /d /c "dumpbin.exe /exports "%s">dumpbin.tmp"', $file), @WorkingDir, @SW_HIDE)
Local $tmp1 = FileRead("dumpbin.tmp")

If Not FileChangeDir($outputdir) Then
	$msgbox(0, 'failed to create folder', $outputdir)
	Exit
EndIf
Local $module = StringRegExp($tmp1, '(?:[\r\n]\s*Dump of file\s+)(\S+[^\r\n]+)', 1)
If @error Then
	$msgbox(0, 'dump failed', $file)
	Exit
EndIf
$module = StringRegExp($module[0], '[^\\/]+$', 1)
$module = StringRegExpReplace($module[0], '\s+$', '', 1)

Local $tmp2 = StringRegExp($tmp1, '(?:[\r\n]\s+ordinal\s+hint\s+RVA\s+name\s*[\r\n])([\s\S]+)(?:[\r\n]\s+Summary\s*[\r\n])', 1)
If @error Then
	$msgbox(0, 'failed to fetch exports', $file)
	Exit
EndIf


Local $cmake = _
		'cmake_minimum_required(VERSION 3.15)' & @CRLF & @CRLF & _
		'project(untitled)' & @CRLF & _
		'enable_language(C CXX ASM_MASM)' & @CRLF & _
		'set(CMAKE_CXX_STANDARD 14)' & @CRLF & @CRLF & _
		'#if ( "${CMAKE_SIZEOF_VOID_P}" STREQUAL "8" )' & @CRLF & _
		'#    add_compile_definitions(X64=1)' & @CRLF & _
		'#endif()' & @CRLF & @CRLF & _
		'add_library(untitled SHARED' & @CRLF & _
		'        "<CODE-FILE-NAME>.obj.asm"' & @CRLF & _
		'        "<CODE-FILE-NAME>.cpp"' & @CRLF & _
		'        "<CODE-FILE-NAME>.def"' & @CRLF & _
		'        )' & @CRLF & _
		'target_link_libraries(untitled PRIVATE' & @CRLF & _
		'        "user32"' & @CRLF & _
		'        "shlwapi"' & @CRLF & _
		'        )' & @CRLF & _
		'set_target_properties(untitled PROPERTIES' & @CRLF & _
		'        PREFIX ""' & @CRLF & _
		'        OUTPUT_NAME "<CODE-FILE-NAME>"' & @CRLF & _
		'        SUFFIX ""' & @CRLF & _
		'        )' & @CRLF & _
		'if ( "${CMAKE_SIZEOF_VOID_P}" STREQUAL "8" )' & @CRLF & _
		'    set_source_files_properties("<CODE-FILE-NAME>.obj.asm" PROPERTIES COMPILE_FLAGS " /nologo -DX64")' & @CRLF & _
		'else()' & @CRLF & _
		'    set_source_files_properties("<CODE-FILE-NAME>.obj.asm" PROPERTIES COMPILE_FLAGS " /nologo /safeseh")' & @CRLF & _
		'endif()' & @CRLF & @CRLF

$cmake = StringReplace($cmake, '<CODE-FILE-NAME>', $module, 0, 1)


Local $cpp = StringFormat('#include <windows.h>\n#include <shlwapi.h>\n\nextern "C" {\n')
Local $def = StringFormat('LIBRARY "%s"\nEXPORTS\n\n', $module)
Local $asm = _
		'ifndef X64' & @CRLF & _
		'.686p' & @CRLF & _
		'.XMM' & @CRLF & _
		'.safeseh SEH_handler' & @CRLF & _
		'.model flat, C' & @CRLF & _
		'option dotname' & @CRLF & _
		'option casemap : none' & @CRLF & _
		'endif' & @CRLF & @CRLF & _
		'<GLOBAL-VAR-DEFINE-HERE>' & @CRLF & @CRLF & _
		'.code' & @CRLF & @CRLF & _
		'align 16' & @CRLF & _
		'SEH_handler   proc' & @CRLF & _
		'; handler' & @CRLF & _
		'ret' & @CRLF & _
		'SEH_handler   endp' & @CRLF & @CRLF
$asm = StringReplace($asm, @CRLF, @LF, 0, 1)
Local $asm_varnames = ''
Local $cpp_loader = ''

Local $lines = StringSplit($tmp2[0], @CRLF)
For $a = 1 To $lines[0]
	Local $tmp3 = $lines[$a]
	
	; ignore c++ symbol
	If StringRegExp($tmp3, '[^\w\s]') Then ContinueLoop

	Local $ordinal = StringRegExp($tmp3, '^(?:\s*)(\w+)', 1)
	If @error Then ContinueLoop
	
	Local $name = StringRegExp($tmp3, '([\w\[\]]+$)', 1)
	If @error Then ContinueLoop
	
	$ordinal = Number($ordinal[0])
	$name = $name[0]
	
	If 'DllMain' == $name Then ContinueLoop

	Local $tmp4 = StringRegExp($name, '\W')
	If $tmp4 Then $name = StringFormat('noname_funcid_%d', $ordinal)
	
	$cpp &= StringFormat('extern void *ptr_%s;\n', $name)
	$cpp &= StringFormat('void *ptr_%s = NULL;\n', $name)
	
	$def &= StringFormat('%s @%d\n', $name, $ordinal)
	
	$asm_varnames &= StringFormat('extern ptr_%s : PTR;\n', $name)
	$asm &= StringFormat('%s PROC\njmp ptr_%s\n%s ENDP\n\n', $name, $name, $name)
	
	If $tmp4 Then
		$cpp_loader &= StringFormat('   ptr_%s = (__vartype(ptr_%s))GetProcAddress(hModule, (LPCSTR)%s);\n', $name, $name, String($ordinal))
	Else
		$cpp_loader &= StringFormat('   ptr_%s = (__vartype(ptr_%s))GetProcAddress(hModule, "%s");\n', $name, $name, $name)
	EndIf
Next
$cpp &= StringFormat('}\n\n\n')
$asm &= StringFormat('end\n')
$asm = StringReplace($asm, '<GLOBAL-VAR-DEFINE-HERE>', $asm_varnames, 1, 1)


$cpp &= _
		'static HMODULE hModule = NULL;' & @CRLF & _
		'static void module_init()' & @CRLF & _
		'{    ' & @CRLF & _
		'   if (hModule) return;' & @CRLF & _
		'   wchar_t sz_module_file[MAX_PATH];' & @CRLF & _
		'   GetSystemDirectoryW(sz_module_file, MAX_PATH);' & @CRLF & _
		'   wcscat_s(sz_module_file, L"\\<MODULE-NAME-HERE>");' & @CRLF & _
		'   hModule = LoadLibraryW(sz_module_file);' & @CRLF & _
		'   if (!hModule) return;' & @CRLF & @CRLF & _
		'   #define __vartype(x) decltype(x)' & @CRLF & _
		$cpp_loader & _
		'   #undef __vartype' & @CRLF & _
		'}' & @CRLF & @CRLF
$cpp = StringReplace($cpp, '<MODULE-NAME-HERE>', $module, 1, 1)

$cpp &= _
		'extern "C" BOOL __stdcall DllMain( HMODULE hModule,	DWORD ul_reason_for_call,LPVOID lpReserved)' & @CRLF & _
		'{' & @CRLF & _
		'	switch (ul_reason_for_call)' & @CRLF & _
		'	{' & @CRLF & _
		'	case DLL_PROCESS_ATTACH:' & @CRLF & _
		'    {' & @CRLF & _
		'        module_init();' & @CRLF & _
		'        wchar_t tmp1[2048];' & @CRLF & _
		'        GetModuleFileNameW(NULL, tmp1, _countof(tmp1));' & @CRLF & _
		'        PathRemoveExtensionW(tmp1);' & @CRLF & _
		'        wcscat(tmp1, L".hook.dll");' & @CRLF & _
		'        LoadLibraryW(tmp1);' & @CRLF & _
		'        break;' & @CRLF & _
		'    }' & @CRLF & _
		'	case DLL_PROCESS_DETACH:' & @CRLF & _
		'		break;' & @CRLF & _
		'	}' & @CRLF & _
		'	return TRUE;' & @CRLF & _
		'}' & @CRLF & @CRLF

Local $build32 = _
		'@echo off & pushd "%~dp0"' & @CRLF & @CRLF & _
		'ml /nologo /safeseh /c "<CODE-FILE-NAME>.obj.asm"' & @CRLF & _
		'cl /MT /Ox "<CODE-FILE-NAME>.cpp" /link /dll shlwapi.lib /def:"<CODE-FILE-NAME>.def" "<CODE-FILE-NAME>.obj.obj" /out:"x86.<MODULE-NAME-HERE>"' & @CRLF
$build32 = StringReplace($build32, '<MODULE-NAME-HERE>', $module, 1, 1)
$build32 = StringReplace($build32, '<CODE-FILE-NAME>', $module, 0, 1)

Local $build64 = _
		'@echo off & pushd "%~dp0"' & @CRLF & @CRLF & _
		'ml64 /nologo -DX64 /c "<CODE-FILE-NAME>.obj.asm"' & @CRLF & _
		'cl /MT /Ox "<CODE-FILE-NAME>.cpp" /link /dll shlwapi.lib /def:"<CODE-FILE-NAME>.def" "<CODE-FILE-NAME>.obj.obj" /out:"x64.<MODULE-NAME-HERE>"' & @CRLF
$build64 = StringReplace($build64, '<MODULE-NAME-HERE>', $module, 1, 1)
$build64 = StringReplace($build64, '<CODE-FILE-NAME>', $module, 0, 1)

FileWriteString($module & '.x86.cmd', $build32, 10)
FileWriteString($module & '.x64.cmd', $build64, 10)
FileWriteString($module & '.cpp', $cpp)
FileWriteString($module & '.obj.asm', $asm, 10)
FileWriteString($module & '.def', $def)
FileWriteString('CMakeLists.txt', $cmake)


Exit

Func FileWriteString($path, $string, $code = 138)
	Local $f = FileOpen($path, $code)
	FileWrite($f, $string)
	FileClose($f)
EndFunc   ;==>FileWriteString
