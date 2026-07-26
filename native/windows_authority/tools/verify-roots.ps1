[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [ValidateSet('Configure', 'Baseline', 'Smoke', 'Package')][string]$Mode = 'Configure',
    [string]$BuildDir,
    [string]$OutputDir,
    [string]$EvidenceDir,
    [string]$PackageDir,
    [switch]$RetainMutationParent
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$markerBytes = [Text.UTF8Encoding]::new($false).GetBytes("FaultLoom Windows Authority MVP v1`n")
$sourceMarker = '.faultloom-source-root-v1'
$generatedMarker = '.faultloom-generated-root-v1'

if (-not ('FaultLoom.Roots.NativePath' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace FaultLoom.Roots {
  public sealed class PathFacts {
    public string FinalPath { get; private set; }
    public uint Attributes { get; private set; }
    public uint LinkCount { get; private set; }
    internal PathFacts(string path, uint attributes, uint links) {
      FinalPath = path; Attributes = attributes; LinkCount = links;
    }
  }
  public static class NativePath {
    const uint ReadAttributes = 0x80;
    const uint ShareAll = 7;
    const uint OpenExisting = 3;
    const uint BackupSemantics = 0x02000000;
    const uint OpenReparsePoint = 0x00200000;
    [StructLayout(LayoutKind.Sequential)]
    struct FileTime { public uint Low; public uint High; }
    [StructLayout(LayoutKind.Sequential)]
    struct FileInformation {
      public uint Attributes; public FileTime Creation; public FileTime Access;
      public FileTime Write; public uint VolumeSerial;
      public uint SizeHigh; public uint SizeLow; public uint Links;
      public uint IndexHigh; public uint IndexLow;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFile(string name, uint access, uint share,
      IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,
      System.Text.StringBuilder path, uint length, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle handle,
      out FileInformation information);
    public static PathFacts Inspect(string path) {
      using (SafeFileHandle handle = CreateFile(path, ReadAttributes, ShareAll,
          IntPtr.Zero, OpenExisting, BackupSemantics | OpenReparsePoint, IntPtr.Zero)) {
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        var buffer = new System.Text.StringBuilder(32768);
        uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
        if (length == 0 || length >= buffer.Capacity)
          throw new Win32Exception(Marshal.GetLastWin32Error());
        FileInformation info;
        if (!GetFileInformationByHandle(handle, out info))
          throw new Win32Exception(Marshal.GetLastWin32Error());
        return new PathFacts(buffer.ToString(), info.Attributes, info.Links);
      }
    }
  }

  public static class OwnedCreation {
    const uint Delete = 0x00010000;
    const uint ReadData = 0x00000001;
    const uint WriteData = 0x00000002;
    const uint ListDirectory = 0x00000001;
    const uint AddSubdirectory = 0x00000004;
    const uint ReadAttributes = 0x00000080;
    const uint Synchronize = 0x00100000;
    const uint ShareReadWrite = 0x00000003;
    const uint FileOpen = 1;
    const uint FileCreate = 2;
    const uint DirectoryFile = 0x00000001;
    const uint SynchronousIo = 0x00000020;
    const uint NonDirectoryFile = 0x00000040;
    const uint OpenReparsePoint = 0x00200000;
    const uint DirectoryAttribute = 0x00000010;
    const uint NormalAttributes = 0x00000080;
    const uint ReparseAttribute = 0x00000400;

    [StructLayout(LayoutKind.Sequential)]
    struct UnicodeString {
      internal ushort Length;
      internal ushort MaximumLength;
      internal IntPtr Buffer;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct ObjectAttributes {
      internal int Length;
      internal IntPtr RootDirectory;
      internal IntPtr ObjectName;
      internal uint Attributes;
      internal IntPtr SecurityDescriptor;
      internal IntPtr SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct IoStatusBlock { internal IntPtr Status; internal UIntPtr Information; }
    [StructLayout(LayoutKind.Sequential)]
    struct FileTime { internal uint Low; internal uint High; }
    [StructLayout(LayoutKind.Sequential)]
    struct FileInformation {
      internal uint Attributes; internal FileTime Creation; internal FileTime Access;
      internal FileTime Write; internal uint VolumeSerial;
      internal uint SizeHigh; internal uint SizeLow; internal uint Links;
      internal uint IndexHigh; internal uint IndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFile(string name, uint access, uint share,
      IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,
      StringBuilder path, uint length, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle handle,
      out FileInformation information);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteFile(SafeFileHandle handle, byte[] buffer,
      int count, out int written, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool FlushFileBuffers(SafeFileHandle handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetFileInformationByHandle(SafeFileHandle handle,
      int informationClass, IntPtr information, uint size);
    [DllImport("ntdll.dll")]
    static extern int NtCreateFile(out SafeFileHandle handle, uint access,
      ref ObjectAttributes attributes, out IoStatusBlock status, IntPtr allocationSize,
      uint fileAttributes, uint share, uint disposition, uint options,
      IntPtr eaBuffer, uint eaLength);
    [DllImport("ntdll.dll")]
    static extern uint RtlNtStatusToDosError(int status);

    static string Full(string path) {
      return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
    }

    static void ValidateName(string name) {
      if (String.IsNullOrEmpty(name) || name == "." || name == ".." ||
          name.IndexOf(Path.DirectorySeparatorChar) >= 0 ||
          name.IndexOf(Path.AltDirectorySeparatorChar) >= 0)
        throw new ArgumentException("Owned path component is invalid");
    }

    static string FinalPath(SafeFileHandle handle) {
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

    static void Validate(SafeFileHandle handle, string expected, bool directory) {
      if (!FinalPath(handle).Equals(Full(expected), StringComparison.OrdinalIgnoreCase))
        throw new InvalidDataException("Owned path canonical mismatch");
      FileInformation information;
      if (!GetFileInformationByHandle(handle, out information))
        throw new Win32Exception(Marshal.GetLastWin32Error());
      bool actualDirectory = (information.Attributes & DirectoryAttribute) != 0;
      if (actualDirectory != directory || (information.Attributes & ReparseAttribute) != 0 ||
          (!directory && information.Links != 1))
        throw new InvalidDataException("Owned path handle type is invalid");
    }

    static SafeFileHandle OpenAbsoluteDirectory(string path) {
      SafeFileHandle handle = CreateFile(path,
        ListDirectory | AddSubdirectory | ReadAttributes | Synchronize,
        ShareReadWrite, IntPtr.Zero, 3, 0x02000000 | OpenReparsePoint, IntPtr.Zero);
      if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
      try { Validate(handle, path, true); return handle; }
      catch { handle.Dispose(); throw; }
    }

    static SafeFileHandle OpenRelative(SafeFileHandle parent, string name, uint access,
        uint disposition, uint options) {
      ValidateName(name);
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
        attributes.RootDirectory = parent.DangerousGetHandle();
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

    static SafeFileHandle OpenExistingDirectory(SafeFileHandle parent, string name,
        string expected) {
      SafeFileHandle handle = OpenRelative(parent, name,
        ListDirectory | AddSubdirectory | ReadAttributes | Synchronize,
        FileOpen, DirectoryFile | SynchronousIo | OpenReparsePoint);
      try { Validate(handle, expected, true); return handle; }
      catch { handle.Dispose(); throw; }
    }

    static SafeFileHandle CreateDirectory(SafeFileHandle parent, string name,
        string expected) {
      SafeFileHandle handle = OpenRelative(parent, name,
        Delete | ListDirectory | AddSubdirectory | ReadAttributes | Synchronize,
        FileCreate, DirectoryFile | SynchronousIo | OpenReparsePoint);
      try { Validate(handle, expected, true); return handle; }
      catch { MarkDeleteNoThrow(handle); handle.Dispose(); throw; }
    }

    static SafeFileHandle CreateMarker(SafeFileHandle parent, string name,
        string expected, byte[] bytes) {
      SafeFileHandle handle = OpenRelative(parent, name,
        Delete | ReadData | WriteData | ReadAttributes | Synchronize,
        FileCreate, NonDirectoryFile | SynchronousIo | OpenReparsePoint);
      try {
        int written;
        if (!WriteFile(handle, bytes, bytes.Length, out written, IntPtr.Zero) ||
            written != bytes.Length) throw new Win32Exception(Marshal.GetLastWin32Error());
        if (!FlushFileBuffers(handle)) throw new Win32Exception(Marshal.GetLastWin32Error());
        Validate(handle, expected, false);
        return handle;
      } catch { MarkDeleteNoThrow(handle); handle.Dispose(); throw; }
    }

    static void MarkDeleteNoThrow(SafeFileHandle handle) {
      if (handle == null || handle.IsInvalid) return;
      IntPtr buffer = Marshal.AllocHGlobal(4);
      try {
        Marshal.WriteInt32(buffer, 1);
        SetFileInformationByHandle(handle, 4, buffer, 4);
      } finally { Marshal.FreeHGlobal(buffer); }
    }

    static List<SafeFileHandle> OpenChain(string repository, string parent) {
      string root = Full(repository);
      string target = Full(parent);
      if (!target.Equals(root, StringComparison.OrdinalIgnoreCase) &&
          !target.StartsWith(root + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase))
        throw new ArgumentException("Owned parent escapes the repository");
      List<SafeFileHandle> chain = new List<SafeFileHandle>();
      try {
        SafeFileHandle current = OpenAbsoluteDirectory(root);
        chain.Add(current);
        if (target.Equals(root, StringComparison.OrdinalIgnoreCase)) return chain;
        string path = root;
        string relative = target.Substring(root.Length).TrimStart(Path.DirectorySeparatorChar);
        foreach (string part in relative.Split(Path.DirectorySeparatorChar)) {
          path = Path.Combine(path, part);
          current = OpenExistingDirectory(current, part, path);
          chain.Add(current);
        }
        return chain;
      } catch {
        DisposeReverse(chain);
        throw;
      }
    }

    static void DisposeReverse(List<SafeFileHandle> handles) {
      for (int index = handles.Count - 1; index >= 0; --index) handles[index].Dispose();
    }

    public static void CreateRoot(string repositoryPath, string existingParentPath,
        string rootPath, string markerName, byte[] markerBytes) {
      if (repositoryPath == null || existingParentPath == null || rootPath == null ||
          markerBytes == null)
        throw new ArgumentNullException();
      string repository = Full(repositoryPath);
      string existingParent = Full(existingParentPath);
      string root = Full(rootPath);
      if ((!existingParent.Equals(repository, StringComparison.OrdinalIgnoreCase) &&
           !existingParent.StartsWith(repository + Path.DirectorySeparatorChar,
             StringComparison.OrdinalIgnoreCase)) ||
          !root.StartsWith(existingParent + Path.DirectorySeparatorChar,
          StringComparison.OrdinalIgnoreCase))
        throw new ArgumentException("Owned root escapes the repository");
      List<SafeFileHandle> chain = OpenChain(repository, existingParent);
      List<SafeFileHandle> created = new List<SafeFileHandle>();
      SafeFileHandle marker = null;
      try {
        SafeFileHandle current = chain[chain.Count - 1];
        string path = existingParent;
        string relative = root.Substring(existingParent.Length).TrimStart(Path.DirectorySeparatorChar);
        string[] parts = relative.Split(Path.DirectorySeparatorChar);
        for (int index = 0; index < parts.Length; ++index) {
          path = Path.Combine(path, parts[index]);
          current = CreateDirectory(current, parts[index], path);
          created.Add(current);
          chain.Add(current);
        }
        marker = CreateMarker(current, markerName, Path.Combine(root, markerName), markerBytes);
      } catch {
        MarkDeleteNoThrow(marker);
        if (marker != null) marker.Dispose();
        for (int index = created.Count - 1; index >= 0; --index) {
          MarkDeleteNoThrow(created[index]);
          created[index].Dispose();
        }
        throw;
      } finally {
        if (marker != null) marker.Dispose();
        DisposeReverse(chain);
      }
    }

    public static void CreateOwnedLeaf(string repositoryPath, string parentPath,
        string leafName, byte[] markerBytes) {
      if (repositoryPath == null || parentPath == null || markerBytes == null)
        throw new ArgumentNullException();
      ValidateName(leafName);
      string parent = Full(parentPath);
      string leafPath = Path.Combine(parent, leafName);
      string markerName = "." + leafName + ".faultloom-owned-v1";
      List<SafeFileHandle> chain = OpenChain(repositoryPath, parent);
      SafeFileHandle directory = null;
      SafeFileHandle marker = null;
      try {
        SafeFileHandle parentHandle = chain[chain.Count - 1];
        directory = CreateDirectory(parentHandle, leafName, leafPath);
        marker = CreateMarker(parentHandle, markerName,
          Path.Combine(parent, markerName), markerBytes);
      } catch {
        MarkDeleteNoThrow(marker);
        if (marker != null) marker.Dispose();
        MarkDeleteNoThrow(directory);
        if (directory != null) directory.Dispose();
        throw;
      } finally {
        if (marker != null) marker.Dispose();
        if (directory != null) directory.Dispose();
        DisposeReverse(chain);
      }
    }
  }
}
'@
}

function Get-FullPath([string]$Path) {
    return [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar)
}

function Get-CanonicalPath([string]$Path) {
    $facts = [FaultLoom.Roots.NativePath]::Inspect($Path)
    if (($facts.Attributes -band 0x400) -ne 0) { throw "Reparse point rejected: $Path" }
    if ((($facts.Attributes -band 0x10) -eq 0) -and $facts.LinkCount -ne 1) {
        throw "Multiply-linked target rejected: $Path"
    }
    $value = $facts.FinalPath
    if ($value.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) {
        return '\\' + $value.Substring(8)
    }
    if ($value.StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase)) {
        return $value.Substring(4)
    }
    return $value
}

function Assert-Beneath([string]$Root, [string]$Candidate) {
    $rootPrefix = $Root + [IO.Path]::DirectorySeparatorChar
    if (($Candidate -ne $Root) -and
        (-not $Candidate.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase))) {
        throw "Path escapes the repository root: $Candidate"
    }
}

function Assert-ExistingChain([string]$Root, [string]$Candidate) {
    Assert-Beneath $Root $Candidate
    $relative = $Candidate.Substring($Root.Length).TrimStart('\')
    $current = $Root
    if ($relative.Length -eq 0) { return }
    foreach ($part in $relative.Split('\')) {
        $current = Join-Path $current $part
        if (-not [IO.Directory]::Exists($current) -and -not [IO.File]::Exists($current)) { break }
        $canonical = Get-CanonicalPath $current
        Assert-Beneath $Root $canonical
        if (-not $canonical.Equals($current, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Canonical path mismatch: $current"
        }
    }
}

function Assert-Marker([string]$Path) {
    if (-not [IO.File]::Exists($Path)) { throw "Required ownership marker is missing: $Path" }
    $canonical = Get-CanonicalPath $Path
    if (-not $canonical.Equals((Get-FullPath $Path), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Marker canonical path mismatch: $Path"
    }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    try {
        $actual = [byte[]]::new($stream.Length)
        $read = $stream.Read($actual, 0, $actual.Length)
        if ($read -ne $actual.Length) { throw "Ownership marker read was incomplete: $Path" }
    } finally {
        $stream.Dispose()
    }
    if ($actual.Length -ne $markerBytes.Length) { throw "Malformed ownership marker: $Path" }
    for ($index = 0; $index -lt $actual.Length; ++$index) {
        if ($actual[$index] -ne $markerBytes[$index]) { throw "Malformed ownership marker: $Path" }
    }
}

function Confirm-Root([string]$Root, [string]$MarkerName, [bool]$MayCreate) {
    if ([IO.Directory]::Exists($Root)) {
        Assert-ExistingChain $script:repository $Root
        Assert-Marker (Join-Path $Root $MarkerName)
        return
    }
    if (-not $MayCreate) { throw "Required source root is missing: $Root" }
    $parent = Split-Path -Parent $Root
    $existingParent = $parent
    while (-not [IO.Directory]::Exists($existingParent)) {
        if ($existingParent.Equals($script:repository, [StringComparison]::OrdinalIgnoreCase)) {
            throw "No existing repository parent for owned root: $Root"
        }
        $existingParent = Split-Path -Parent $existingParent
    }
    Assert-ExistingChain $script:repository $existingParent
    [FaultLoom.Roots.OwnedCreation]::CreateRoot(
        $script:repository, $existingParent, $Root, $MarkerName, $markerBytes)
}

function Confirm-OwnedLeaf([string]$Leaf, [string]$Parent) {
    $leafName = Split-Path -Leaf $Leaf
    $leafMarker = Join-Path $Parent ('.' + $leafName + '.faultloom-owned-v1')
    if ([IO.Directory]::Exists($Leaf)) {
        Assert-ExistingChain $script:repository $Leaf
        Assert-Marker $leafMarker
        return
    }
    if ([IO.File]::Exists($Leaf) -or [IO.File]::Exists($leafMarker) -or [IO.Directory]::Exists($leafMarker)) {
        throw "Owned leaf cannot be safely created: $Leaf"
    }
    Assert-ExistingChain $script:repository $Parent
    [FaultLoom.Roots.OwnedCreation]::CreateOwnedLeaf(
        $script:repository, $Parent, $leafName, $markerBytes)
}

function Assert-OwnedMembership([string]$Parent, [string]$InternalMarker) {
    $suffix = '.faultloom-owned-v1'
    foreach ($entry in [IO.Directory]::GetFileSystemEntries($Parent)) {
        $name = Split-Path -Leaf $entry
        if ($name.Equals($InternalMarker, [StringComparison]::Ordinal)) { continue }
        if ([IO.Directory]::Exists($entry)) {
            $sibling = Join-Path $Parent ('.' + $name + '.faultloom-owned-v1')
            Assert-Marker $sibling
            Assert-ExistingChain $script:repository $entry
            continue
        }
        if ($name.StartsWith('.', [StringComparison]::Ordinal) -and
            $name.EndsWith($suffix, [StringComparison]::Ordinal)) {
            $leafName = $name.Substring(1, $name.Length - 1 - $suffix.Length)
            $leaf = Join-Path $Parent $leafName
            if (-not [IO.Directory]::Exists($leaf)) { throw "Orphan ownership marker rejected: $entry" }
            Assert-Marker $entry
            continue
        }
        throw "Foreign member rejected: $entry"
    }
}

$repositoryInput = Get-FullPath $RepositoryRoot
if (-not $RetainMutationParent -and -not [IO.Directory]::Exists($repositoryInput)) {
    throw 'Repository root does not exist'
}
$repository = $repositoryInput
$sourceRoot = Join-Path $repository 'native\windows_authority'
$generatedRoot = Join-Path $repository 'out\windows_authority'
$retainedMutationParent = $null

if ($RetainMutationParent) {
    if (-not ('FaultLoom.Capture.OwnedParentSession' -as [type])) {
        throw 'Retained publication-parent support is not loaded'
    }
    if ($Mode -eq 'Smoke') {
        if ([string]::IsNullOrWhiteSpace($BuildDir) -or
            [string]::IsNullOrWhiteSpace($EvidenceDir)) {
            throw 'BuildDir and EvidenceDir are required'
        }
        $expectedBuild = Join-Path $generatedRoot 'build'
        if (-not (Get-FullPath $BuildDir).Equals(
                $expectedBuild, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'BuildDir must be the exact owned build leaf'
        }
        $mutationParent = Join-Path $generatedRoot 'smoke-evidence'
        if (-not (Split-Path -Parent (Get-FullPath $EvidenceDir)).Equals(
                $mutationParent, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'EvidenceDir must be a direct child of the owned smoke-evidence leaf'
        }
    } elseif ($Mode -eq 'Package') {
        $creating = -not [string]::IsNullOrWhiteSpace($OutputDir)
        $verifying = -not [string]::IsNullOrWhiteSpace($PackageDir)
        if ($creating -eq $verifying) { throw 'Supply exactly one of OutputDir or PackageDir' }
        if (-not $creating) { throw 'Package verification cannot retain a mutation parent' }
        if ([string]::IsNullOrWhiteSpace($BuildDir)) { throw 'BuildDir is required' }
        $expectedBuild = Join-Path $generatedRoot 'build'
        if (-not (Get-FullPath $BuildDir).Equals(
                $expectedBuild, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'BuildDir must be the exact owned build leaf'
        }
        $mutationParent = Join-Path $generatedRoot 'package'
        if (-not (Split-Path -Parent (Get-FullPath $OutputDir)).Equals(
                $mutationParent, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'OutputDir must be a direct child of the owned package leaf'
        }
    } else {
        throw 'Only Package and Smoke mutation can retain a parent'
    }
    $retainedMutationParent = [FaultLoom.Capture.OwnedParentSession]::OpenAndVerify(
        $repository, $mutationParent, $markerBytes)
} else {
    $repository = Get-CanonicalPath $repositoryInput
    if (-not $repository.Equals($repositoryInput, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Repository root must be supplied by its canonical path'
    }
    $sourceRoot = Join-Path $repository 'native\windows_authority'
    $generatedRoot = Join-Path $repository 'out\windows_authority'
    $generatedRootMayCreate = $Mode -notin @('Package', 'Smoke')
    Confirm-Root $sourceRoot $sourceMarker $false
    Confirm-Root $generatedRoot $generatedMarker $generatedRootMayCreate
}

try {
Assert-OwnedMembership $generatedRoot $generatedMarker

switch ($Mode) {
    'Configure' {
        if ([string]::IsNullOrWhiteSpace($BuildDir)) { throw 'BuildDir is required' }
        $build = Get-FullPath $BuildDir
        $expected = Join-Path $generatedRoot 'build'
        if (-not $build.Equals($expected, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'BuildDir must be the exact owned build leaf'
        }
        Confirm-OwnedLeaf $build $generatedRoot
    }
    'Baseline' {
        if ([string]::IsNullOrWhiteSpace($OutputDir)) { throw 'OutputDir is required' }
        $baseline = Join-Path $generatedRoot 'baseline'
        Confirm-OwnedLeaf $baseline $generatedRoot
        Assert-OwnedMembership $baseline ''
        $output = Get-FullPath $OutputDir
        if (-not (Split-Path -Parent $output).Equals($baseline, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'OutputDir must be a direct child of the owned baseline leaf'
        }
        Assert-ExistingChain $repository $output
        $outputMarker = Join-Path $baseline ('.' + (Split-Path -Leaf $output) + '.faultloom-owned-v1')
        if ([IO.Directory]::Exists($output) -or [IO.File]::Exists($output) -or
            [IO.File]::Exists($outputMarker) -or [IO.Directory]::Exists($outputMarker)) {
            throw 'Baseline output must be a new owned leaf'
        }
    }
    'Smoke' {
        if ([string]::IsNullOrWhiteSpace($BuildDir) -or
            [string]::IsNullOrWhiteSpace($EvidenceDir)) {
            throw 'BuildDir and EvidenceDir are required'
        }
        $build = Get-FullPath $BuildDir
        $expectedBuild = Join-Path $generatedRoot 'build'
        if (-not $build.Equals($expectedBuild, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'BuildDir must be the exact owned build leaf'
        }
        Confirm-OwnedLeaf $build $generatedRoot
        $smokeRoot = Join-Path $generatedRoot 'smoke-evidence'
        if (-not $RetainMutationParent) { Confirm-OwnedLeaf $smokeRoot $generatedRoot }
        Assert-OwnedMembership $smokeRoot ''
        $evidence = Get-FullPath $EvidenceDir
        if (-not (Split-Path -Parent $evidence).Equals(
                $smokeRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'EvidenceDir must be a direct child of the owned smoke-evidence leaf'
        }
        Assert-ExistingChain $repository $evidence
        $evidenceMarker = Join-Path $smokeRoot (
            '.' + (Split-Path -Leaf $evidence) + '.faultloom-owned-v1')
        if ([IO.Directory]::Exists($evidence) -or [IO.File]::Exists($evidence) -or
            [IO.File]::Exists($evidenceMarker) -or [IO.Directory]::Exists($evidenceMarker)) {
            throw 'Smoke evidence output must be a new owned leaf'
        }
    }
    'Package' {
        $creating = -not [string]::IsNullOrWhiteSpace($OutputDir)
        $verifying = -not [string]::IsNullOrWhiteSpace($PackageDir)
        if ($creating -eq $verifying) { throw 'Supply exactly one of OutputDir or PackageDir' }
        $packageRoot = Join-Path $generatedRoot 'package'
        if ($verifying -and -not [IO.Directory]::Exists($packageRoot)) {
            throw 'Required package root is missing'
        }
        if (-not $RetainMutationParent) { Confirm-OwnedLeaf $packageRoot $generatedRoot }
        Assert-OwnedMembership $packageRoot ''
        if ($creating) {
            if ([string]::IsNullOrWhiteSpace($BuildDir)) { throw 'BuildDir is required' }
            $build = Get-FullPath $BuildDir
            $expectedBuild = Join-Path $generatedRoot 'build'
            if (-not $build.Equals($expectedBuild, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'BuildDir must be the exact owned build leaf'
            }
            Confirm-OwnedLeaf $build $generatedRoot
            $output = Get-FullPath $OutputDir
            if (-not (Split-Path -Parent $output).Equals(
                    $packageRoot, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'OutputDir must be a direct child of the owned package leaf'
            }
            Assert-ExistingChain $repository $output
            $outputMarker = Join-Path $packageRoot (
                '.' + (Split-Path -Leaf $output) + '.faultloom-owned-v1')
            if ([IO.Directory]::Exists($output) -or [IO.File]::Exists($output) -or
                [IO.File]::Exists($outputMarker) -or [IO.Directory]::Exists($outputMarker)) {
                throw 'Package output must be a new owned leaf'
            }
        } else {
            if ($RetainMutationParent) {
                throw 'Package verification cannot retain a mutation parent'
            }
            $package = Get-FullPath $PackageDir
            if (-not (Split-Path -Parent $package).Equals(
                    $packageRoot, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'PackageDir must be a direct child of the owned package leaf'
            }
            if (-not [IO.Directory]::Exists($package)) { throw 'PackageDir does not exist' }
            Confirm-OwnedLeaf $package $packageRoot
        }
    }
}

[Console]::Out.WriteLine('ROOT_PREFLIGHT_OK')
if ($RetainMutationParent) {
    if ($null -eq $retainedMutationParent) {
        throw 'Requested mutation parent was not retained'
    }
    $returnedMutationParent = $retainedMutationParent
    $retainedMutationParent = $null
    Write-Output -NoEnumerate $returnedMutationParent
}
} finally {
    if ($null -ne $retainedMutationParent) { $retainedMutationParent.Dispose() }
}
