# Microsoft Visual C++ generated build script - Do not modify

PROJ = ATTACHER
DEBUG = 1
PROGTYPE = 0
CALLER = 
ARGS = 
DLLS = 
D_RCDEFINES = -d_DEBUG
R_RCDEFINES = -dNDEBUG
ORIGIN = MSVC
ORIGIN_VER = 1.00
PROJPATH = C:\ATTACHER\
USEMFC = 0
CC = cl
CPP = cl
CXX = cl
CCREATEPCHFLAG = 
CPPCREATEPCHFLAG = 
CUSEPCHFLAG = 
CPPUSEPCHFLAG = 
FIRSTC = ATT2.C      
FIRSTCPP =             
RC = rc
CFLAGS_D_WEXE = /nologo /G2 /W4 /Zi /AM /Od /D "_DEBUG" /FR /GA /Fd"ATTACHER.PDB"
CFLAGS_R_WEXE = /nologo /W4 /AM /O1 /D "NDEBUG" /FR /GA 
LFLAGS_D_WEXE = /NOLOGO /NOD /PACKC:61440 /STACK:10240 /ALIGN:16 /ONERROR:NOEXE /CO  
LFLAGS_R_WEXE = /NOLOGO /NOD /PACKC:61440 /STACK:10240 /ALIGN:16 /ONERROR:NOEXE  
LIBS_D_WEXE = oldnames libw mlibcew nwcalls.lib commdlg.lib olecli.lib olesvr.lib shell.lib 
LIBS_R_WEXE = oldnames libw mlibcew nwcalls.lib commdlg.lib olecli.lib olesvr.lib shell.lib 
RCFLAGS = /nologo
RESFLAGS = /nologo
RUNFLAGS = 
DEFFILE = ATTACHER.DEF
OBJS_EXT = 
LIBS_EXT = 
!if "$(DEBUG)" == "1"
CFLAGS = $(CFLAGS_D_WEXE)
LFLAGS = $(LFLAGS_D_WEXE)
LIBS = $(LIBS_D_WEXE)
MAPFILE = nul
RCDEFINES = $(D_RCDEFINES)
!else
CFLAGS = $(CFLAGS_R_WEXE)
LFLAGS = $(LFLAGS_R_WEXE)
LIBS = $(LIBS_R_WEXE)
MAPFILE = nul
RCDEFINES = $(R_RCDEFINES)
!endif
!if [if exist MSVC.BND del MSVC.BND]
!endif
SBRS = ATT2.SBR


ATT2_DEP = i:\client\include\nwcalls.h \
	i:\client\include\nwcaldef.h \
	i:\client\include\nwalias.h \
	i:\client\include\nwafp.h \
	i:\client\include\nwbindry.h \
	i:\client\include\nwconnec.h \
	i:\client\include\nwdel.h \
	i:\client\include\nwdentry.h \
	i:\client\include\nwdirect.h \
	i:\client\include\nwdpath.h \
	i:\client\include\nwea.h \
	i:\client\include\nwnamspc.h \
	i:\client\include\nwerror.h \
	i:\client\include\nwfile.h \
	i:\client\include\nwmisc.h \
	i:\client\include\nwmsg.h \
	i:\client\include\nwprint.h \
	i:\client\include\nwqms.h \
	i:\client\include\nwserver.h \
	i:\client\include\nwsync.h \
	i:\client\include\nwtts.h \
	i:\client\include\nwvol.h \
	i:\client\include\nwacct.h \
	i:\client\include\nwfse.h \
	i:\client\include\nwmigrat.h


all:	$(PROJ).EXE $(PROJ).BSC

ATT2.OBJ:	ATT2.C $(ATT2_DEP)
	$(CC) $(CFLAGS) $(CCREATEPCHFLAG) /c ATT2.C


$(PROJ).EXE::	ATT2.OBJ $(OBJS_EXT) $(DEFFILE)
	echo >NUL @<<$(PROJ).CRF
ATT2.OBJ +
$(OBJS_EXT)
$(PROJ).EXE
$(MAPFILE)
h:\msvc15\lib\+
h:\msvc15\mfc\lib\+
i:\workshop\doswin\toolkit\lib\+
i:\client\win\+
$(LIBS)
$(DEFFILE);
<<
	link $(LFLAGS) @$(PROJ).CRF
	$(RC) $(RESFLAGS) $@


run: $(PROJ).EXE
	$(PROJ) $(RUNFLAGS)


$(PROJ).BSC: $(SBRS)
	bscmake @<<
/o$@ $(SBRS)
<<
