using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace FaultLoom.Capture {
  internal static class NativeMethods {
    internal const uint Delete = 0x00010000;
    internal const uint ReadData = 0x00000001;
    internal const uint WriteData = 0x00000002;
    internal const uint AddSubdirectory = 0x00000004;
    internal const uint ListDirectory = 0x00000001;
    internal const uint ReadAttributes = 0x00000080;
    internal const uint Synchronize = 0x00100000;
    internal const uint ShareAll = 0x00000007;
    internal const uint ShareReadWrite = 0x00000003;
    internal const uint FileCreate = 2;
    internal const uint FileOpen = 1;
    internal const uint DirectoryFile = 0x00000001;
    internal const uint NonDirectoryFile = 0x00000040;
    internal const uint SynchronousIo = 0x00000020;
    internal const uint OpenReparsePoint = 0x00200000;
    internal const uint NormalAttributes = 0x00000080;
    internal const uint ReparseAttribute = 0x00000400;
    internal const uint DirectoryAttribute = 0x00000010;
    internal const int NoMoreFiles = unchecked((int)0x80000006);

    [StructLayout(LayoutKind.Sequential)]
    internal struct UnicodeString {
      internal ushort Length;
      internal ushort MaximumLength;
      internal IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ObjectAttributes {
      internal int Length;
      internal IntPtr RootDirectory;
      internal IntPtr ObjectName;
      internal uint Attributes;
      internal IntPtr SecurityDescriptor;
      internal IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IoStatusBlock {
      internal IntPtr Status;
      internal UIntPtr Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FileTime {
      internal uint Low;
      internal uint High;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FileInformation {
      internal uint Attributes;
      internal FileTime Creation;
      internal FileTime Access;
      internal FileTime Write;
      internal uint VolumeSerial;
      internal uint SizeHigh;
      internal uint SizeLow;
      internal uint Links;
      internal uint IndexHigh;
      internal uint IndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFile(string name, uint access, uint share,
      IntPtr security, uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,
      StringBuilder path, uint length, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool GetFileInformationByHandle(SafeFileHandle handle,
      out FileInformation information);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool GetFileSizeEx(SafeFileHandle handle, out long size);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool SetFilePointerEx(SafeFileHandle handle, long distance,
      out long newPosition, uint moveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool ReadFile(SafeFileHandle handle, byte[] buffer,
      int count, out int read, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool WriteFile(SafeFileHandle handle, byte[] buffer,
      int count, out int written, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool FlushFileBuffers(SafeFileHandle handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool SetFileInformationByHandle(SafeFileHandle handle,
      int informationClass, IntPtr information, uint size);

    [DllImport("ntdll.dll")]
    static extern int NtCreateFile(out SafeFileHandle handle, uint access,
      ref ObjectAttributes attributes, out IoStatusBlock status, IntPtr allocationSize,
      uint fileAttributes, uint share, uint disposition, uint options,
      IntPtr eaBuffer, uint eaLength);

    [DllImport("ntdll.dll")]
    static extern int NtQueryDirectoryFile(SafeFileHandle handle, IntPtr eventHandle,
      IntPtr apcRoutine, IntPtr apcContext, out IoStatusBlock status, IntPtr information,
      uint length, int informationClass, bool singleEntry, IntPtr fileName, bool restartScan);

    [DllImport("ntdll.dll")]
    static extern int NtSetInformationFile(SafeFileHandle handle, out IoStatusBlock status,
      IntPtr information, uint length, int informationClass);

    [DllImport("ntdll.dll")]
    static extern uint RtlNtStatusToDosError(int status);

    internal static SafeFileHandle OpenBaseline(string path) {
      SafeFileHandle handle = CreateFile(path, ListDirectory | AddSubdirectory | ReadAttributes | Synchronize,
        ShareReadWrite, IntPtr.Zero, 3, 0x02000000 | OpenReparsePoint, IntPtr.Zero);
      if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
      return handle;
    }

    internal static SafeFileHandle OpenDirectory(string path, bool allowCreate) {
      uint access = ListDirectory | ReadAttributes | Synchronize;
      if (allowCreate) access |= AddSubdirectory;
      SafeFileHandle handle = CreateFile(path, access, ShareReadWrite, IntPtr.Zero, 3,
        0x02000000 | OpenReparsePoint, IntPtr.Zero);
      if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
      return handle;
    }

    internal static SafeFileHandle OpenRelative(SafeFileHandle root, string name,
        uint access, uint disposition, uint options) {
      IntPtr text = Marshal.StringToHGlobalUni(name);
      IntPtr unicode = IntPtr.Zero;
      try {
        UnicodeString value = new UnicodeString();
        value.Length = checked((ushort)(name.Length * 2));
        value.MaximumLength = checked((ushort)(value.Length + 2));
        value.Buffer = text;
        unicode = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
        Marshal.StructureToPtr(value, unicode, false);
        ObjectAttributes attributes = new ObjectAttributes();
        attributes.Length = Marshal.SizeOf(typeof(ObjectAttributes));
        attributes.RootDirectory = root.DangerousGetHandle();
        attributes.ObjectName = unicode;
        attributes.Attributes = 0x40;
        IoStatusBlock io;
        SafeFileHandle handle;
        int status = NtCreateFile(out handle, access, ref attributes, out io, IntPtr.Zero,
          NormalAttributes, ShareReadWrite, disposition, options, IntPtr.Zero, 0);
        if (status < 0) {
          if (handle != null) handle.Dispose();
          throw new Win32Exception((int)RtlNtStatusToDosError(status));
        }
        return handle;
      } finally {
        if (unicode != IntPtr.Zero) Marshal.FreeHGlobal(unicode);
        Marshal.FreeHGlobal(text);
      }
    }

    internal static string FinalPath(SafeFileHandle handle) {
      StringBuilder buffer = new StringBuilder(32768);
      uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
      if (length == 0 || length >= buffer.Capacity)
        throw new Win32Exception(Marshal.GetLastWin32Error());
      string value = buffer.ToString();
      if (value.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        return @"\\" + value.Substring(8);
      if (value.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
        return value.Substring(4);
      return value;
    }

    internal static List<string> ListNames(SafeFileHandle directory, int maximum) {
      List<string> names = new List<string>();
      IntPtr buffer = Marshal.AllocHGlobal(4096);
      try {
        bool restart = true;
        while (true) {
          IoStatusBlock io;
          int status = NtQueryDirectoryFile(directory, IntPtr.Zero, IntPtr.Zero,
            IntPtr.Zero, out io, buffer, 4096, 12, false, IntPtr.Zero, restart);
          restart = false;
          if (status == NoMoreFiles) break;
          if (status < 0) throw new Win32Exception((int)RtlNtStatusToDosError(status));
          int used = checked((int)io.Information.ToUInt64());
          int offset = 0;
          while (offset < used) {
            int next = Marshal.ReadInt32(buffer, offset);
            int byteLength = Marshal.ReadInt32(buffer, offset + 8);
            if (byteLength < 0 || (byteLength & 1) != 0 || offset + 12 + byteLength > used)
              throw new InvalidDataException("Directory enumeration is malformed");
            string name = Marshal.PtrToStringUni(IntPtr.Add(buffer, offset + 12), byteLength / 2);
            if (name != "." && name != "..") names.Add(name);
            if (names.Count > maximum) throw new InvalidDataException("Temporary leaf has too many members");
            if (next == 0) break;
            if (next < 12 || offset + next > used) throw new InvalidDataException("Directory enumeration is malformed");
            offset += next;
          }
        }
      } finally {
        Marshal.FreeHGlobal(buffer);
      }
      return names;
    }

    internal static void RenameRelative(SafeFileHandle handle, SafeFileHandle root, string name) {
      byte[] encoded = Encoding.Unicode.GetBytes(name);
      IntPtr buffer = Marshal.AllocHGlobal(20 + encoded.Length);
      try {
        for (int index = 0; index < 20 + encoded.Length; ++index) Marshal.WriteByte(buffer, index, 0);
        Marshal.WriteIntPtr(buffer, 8, root.DangerousGetHandle());
        Marshal.WriteInt32(buffer, 16, encoded.Length);
        Marshal.Copy(encoded, 0, IntPtr.Add(buffer, 20), encoded.Length);
        IoStatusBlock io;
        int status = NtSetInformationFile(handle, out io, buffer, (uint)(20 + encoded.Length), 10);
        if (status < 0) throw new Win32Exception((int)RtlNtStatusToDosError(status));
      } finally {
        Marshal.FreeHGlobal(buffer);
      }
    }
  }
}
