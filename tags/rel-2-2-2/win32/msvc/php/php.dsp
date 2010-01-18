# Microsoft Developer Studio Project File - Name="php" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **
# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=php - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "php.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "php.mak" CFG="php - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "php - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "php - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "php - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "PHP_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "h:\lasso-deps\include" /I "h:\lasso-deps\include\glib-2.0" /I "h:\lasso-deps\lib\glib-2.0\include" /I "G:\php\php-4.3.10\TSRM" /I "G:\php\php-4.3.10\win32" /I "G:\php\php-4.3.10\Zend" /I "G:\php\php-4.3.10\main" /I "G:\php\php-4.3.10" /I "..\..\.." /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "PHP_EXPORTS" /D "ZEND_WIN32" /D "PHP_WIN32" /D ZTS=1 /D COMPILE_DL_LASSO=1 /D ZEND_DEBUG=0 /D XMLSEC_CRYPTO=\"openssl\" /D XMLSEC_CRYPTO_DYNAMIC_LOADING=1 /D XMLSEC_LIBXML_260=1 /D XMLSEC_NO_XKMS=1 /D XMLSEC_CRYPTO_OPENSSL=1 /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x40c /d "NDEBUG"
# ADD RSC /l 0x40c /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib php4ts.lib liblasso-3.lib libxml2.lib glib-2.0.lib gobject-2.0.lib /nologo /dll /machine:I386 /out:"Release\php_lasso.dll" /libpath:"G:\php\php-4.3.10-Win32" /libpath:"..\Release" /libpath:"h:\lasso-deps\lib"

!ELSEIF  "$(CFG)" == "php - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "PHP_EXPORTS" /YX /FD /GZ /c
# ADD CPP /nologo /MD /W3 /Gm /GX /ZI /Od /I "h:\lasso-deps\include" /I "h:\lasso-deps\include\glib-2.0" /I "h:\lasso-deps\lib\glib-2.0\include" /I "G:\php\php-4.3.10\TSRM" /I "G:\php\php-4.3.10\win32" /I "G:\php\php-4.3.10\Zend" /I "G:\php\php-4.3.10\main" /I "G:\php\php-4.3.10" /I "..\..\.." /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "PHP_EXPORTS" /D "ZEND_WIN32" /D "PHP_WIN32" /D ZTS=1 /D COMPILE_DL_LASSO=1 /D ZEND_DEBUG=0 /D XMLSEC_CRYPTO=\"openssl\" /D XMLSEC_CRYPTO_DYNAMIC_LOADING=1 /D XMLSEC_LIBXML_260=1 /D XMLSEC_NO_XKMS=1 /D XMLSEC_CRYPTO_OPENSSL=1 /YX /FD /TC /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x40c /d "_DEBUG"
# ADD RSC /l 0x40c /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib php4ts.lib liblasso-3.lib libxml2.lib glib-2.0.lib gobject-2.0.lib /nologo /dll /debug /machine:I386 /out:"Debug\php_lasso.dll" /pdbtype:sept /libpath:"G:\php\php-4.3.10-Win32" /libpath:"..\Debug" /libpath:"h:\lasso-deps\lib"

!ENDIF 

# Begin Target

# Name "php - Win32 Release"
# Name "php - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\..\..\php\lasso_wrap.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\..\..\php\php_lasso.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project
