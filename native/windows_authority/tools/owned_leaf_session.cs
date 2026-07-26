namespace FaultLoom.Capture {
  public sealed class OwnedParentSession : IDisposable {
    struct Identity {
      internal uint Volume;
      internal uint High;
      internal uint Low;
    }

    readonly string parentPath;
    readonly byte[] markerBytes;
    readonly List<SafeFileHandle> directories = new List<SafeFileHandle>();
    readonly List<Identity> directoryIdentities = new List<Identity>();
    SafeFileHandle sourceMarker;
    SafeFileHandle generatedMarker;
    SafeFileHandle marker;
    SafeFileHandle publicationDirectory;
    Identity sourceMarkerIdentity;
    Identity generatedMarkerIdentity;
    Identity markerIdentity;
    bool createdParent;
    bool createdMarker;
    bool disposed;

#if FAULTLOOM_TRANSACTION_TEST_HOOK
    public static Action TestAfterPublicationParentOpened;
#endif

    OwnedParentSession(string parent, byte[] bytes) {
      parentPath = parent;
      markerBytes = (byte[])bytes.Clone();
    }

    internal string PathValue { get { EnsureActive(); return parentPath; } }
    internal SafeFileHandle Directory {
      get { EnsureActive(); return directories[directories.Count - 1]; }
    }
    SafeFileHandle CurrentDirectory { get { return directories[directories.Count - 1]; } }

    public static OwnedParentSession OpenAndVerify(string repositoryPath, string parentPath,
        byte[] markerBytes) {
      if (repositoryPath == null || parentPath == null || markerBytes == null)
        throw new ArgumentNullException();
      string repository = Path.GetFullPath(repositoryPath).TrimEnd(Path.DirectorySeparatorChar);
      string parent = Path.GetFullPath(parentPath).TrimEnd(Path.DirectorySeparatorChar);
      string generated = Path.Combine(repository, "out", "windows_authority");
      string parentName = Path.GetFileName(parent);
      if ((!parentName.Equals("package", StringComparison.Ordinal) &&
           !parentName.Equals("smoke-evidence", StringComparison.Ordinal)) ||
          !parent.Equals(Path.Combine(generated, parentName),
            StringComparison.OrdinalIgnoreCase))
        throw new ArgumentException("Owned parent is not a publication root");
      OwnedParentSession session = new OwnedParentSession(parent, markerBytes);
      try {
        session.Acquire(repository, generated, parentName);
        session.Validate();
        return session;
      } catch {
        session.RollbackCreated();
        session.Dispose();
        throw;
      }
    }

    void Acquire(string repository, string generated, string parentName) {
      RetainDirectory(NativeMethods.OpenDirectory(repository, false), repository);
      string native = Path.Combine(repository, "native");
      RetainDirectory(OpenDirectoryRelative(CurrentDirectory, "native", false), native);
      string source = Path.Combine(native, "windows_authority");
      RetainDirectory(OpenDirectoryRelative(CurrentDirectory, "windows_authority", false), source);
      sourceMarker = OpenMarker(CurrentDirectory, ".faultloom-source-root-v1",
        Path.Combine(source, ".faultloom-source-root-v1"), false);
      sourceMarkerIdentity = ValidateMarker(sourceMarker, markerBytes);

      SafeFileHandle repositoryHandle = directories[0];
      string output = Path.Combine(repository, "out");
      RetainDirectory(OpenDirectoryRelative(repositoryHandle, "out", false), output);
      RetainDirectory(OpenDirectoryRelative(CurrentDirectory, "windows_authority", true), generated);
      generatedMarker = OpenMarker(CurrentDirectory, ".faultloom-generated-root-v1",
        Path.Combine(generated, ".faultloom-generated-root-v1"), false);
      generatedMarkerIdentity = ValidateMarker(generatedMarker, markerBytes);

      SafeFileHandle publication = null;
      try {
        publication = OpenDirectoryRelative(CurrentDirectory, parentName, true);
      } catch (Win32Exception error) {
        if (error.NativeErrorCode != 2 && error.NativeErrorCode != 3) throw;
        publication = NativeMethods.OpenRelative(CurrentDirectory, parentName,
          NativeMethods.Delete | NativeMethods.ListDirectory |
            NativeMethods.AddSubdirectory | NativeMethods.ReadAttributes |
            NativeMethods.Synchronize,
          NativeMethods.FileCreate,
          NativeMethods.DirectoryFile | NativeMethods.SynchronousIo |
            NativeMethods.OpenReparsePoint);
        createdParent = true;
      }
      RetainDirectory(publication, parentPath, createdParent);
      publicationDirectory = publication;
#if FAULTLOOM_TRANSACTION_TEST_HOOK
      Action hook = TestAfterPublicationParentOpened;
      TestAfterPublicationParentOpened = null;
      if (hook != null) hook();
#endif
      string ownerName = "." + parentName + ".faultloom-owned-v1";
      if (createdParent) {
        marker = OpenMarker(generatedMarkerOwner, ownerName,
          Path.Combine(generated, ownerName), true);
        createdMarker = true;
        WriteExact(marker, markerBytes);
      } else {
        marker = OpenMarker(generatedMarkerOwner, ownerName,
          Path.Combine(generated, ownerName), false);
      }
      markerIdentity = ValidateMarker(marker, markerBytes);
    }

    SafeFileHandle generatedMarkerOwner {
      get { return directories[directories.Count - 2]; }
    }

    static SafeFileHandle OpenDirectoryRelative(SafeFileHandle owner, string name,
        bool allowCreate) {
      uint access = NativeMethods.ListDirectory | NativeMethods.ReadAttributes |
        NativeMethods.Synchronize;
      if (allowCreate) access |= NativeMethods.AddSubdirectory;
      return NativeMethods.OpenRelative(owner, name, access, NativeMethods.FileOpen,
        NativeMethods.DirectoryFile | NativeMethods.SynchronousIo |
          NativeMethods.OpenReparsePoint);
    }

    static SafeFileHandle OpenMarker(SafeFileHandle owner, string name, string expected,
        bool create) {
      uint access = NativeMethods.ReadData | NativeMethods.ReadAttributes |
        NativeMethods.Synchronize;
      if (create) access |= NativeMethods.Delete | NativeMethods.WriteData;
      SafeFileHandle handle = NativeMethods.OpenRelative(owner, name, access,
        create ? NativeMethods.FileCreate : NativeMethods.FileOpen,
        NativeMethods.NonDirectoryFile | NativeMethods.SynchronousIo |
          NativeMethods.OpenReparsePoint);
      try {
        if (!NativeMethods.FinalPath(handle).Equals(Path.GetFullPath(expected),
            StringComparison.OrdinalIgnoreCase))
          throw new InvalidDataException("Owned marker path canonical mismatch");
        return handle;
      } catch {
        if (create) MarkDeleteNoThrow(handle);
        handle.Dispose();
        throw;
      }
    }

    void RetainDirectory(SafeFileHandle handle, string expected) {
      RetainDirectory(handle, expected, false);
    }

    void RetainDirectory(SafeFileHandle handle, string expected, bool removeOnFailure) {
      try {
        Identity identity = ValidatePath(handle, expected, true, false);
        directories.Add(handle);
        directoryIdentities.Add(identity);
      } catch {
        if (removeOnFailure) MarkDeleteNoThrow(handle);
        handle.Dispose();
        throw;
      }
    }

    Identity ValidateMarker(SafeFileHandle handle, byte[] expected) {
      Identity identity = ValidateHandle(handle, false, true);
      AssertBytes(ReadHandle(handle, expected.Length), expected);
      return identity;
    }

    static void WriteExact(SafeFileHandle handle, byte[] bytes) {
      int written;
      if (!NativeMethods.WriteFile(handle, bytes, bytes.Length, out written, IntPtr.Zero) ||
          written != bytes.Length) throw new Win32Exception(Marshal.GetLastWin32Error());
      if (!NativeMethods.FlushFileBuffers(handle))
        throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    public void Validate() {
      EnsureActive();
      for (int index = 0; index < directories.Count; ++index)
        CheckIdentity(directories[index], directoryIdentities[index], true, false);
      CheckIdentity(sourceMarker, sourceMarkerIdentity, false, true);
      CheckIdentity(generatedMarker, generatedMarkerIdentity, false, true);
      CheckIdentity(marker, markerIdentity, false, true);
      AssertBytes(ReadHandle(sourceMarker, markerBytes.Length), markerBytes);
      AssertBytes(ReadHandle(generatedMarker, markerBytes.Length), markerBytes);
      AssertBytes(ReadHandle(marker, markerBytes.Length), markerBytes);
    }

    Identity ValidatePath(SafeFileHandle handle, string expected, bool directory, bool oneLink) {
      if (!NativeMethods.FinalPath(handle).Equals(Path.GetFullPath(expected),
          StringComparison.OrdinalIgnoreCase))
        throw new InvalidDataException("Owned parent path canonical mismatch");
      return ValidateHandle(handle, directory, oneLink);
    }

    Identity ValidateHandle(SafeFileHandle handle, bool directory, bool oneLink) {
      NativeMethods.FileInformation info;
      if (!NativeMethods.GetFileInformationByHandle(handle, out info))
        throw new Win32Exception(Marshal.GetLastWin32Error());
      bool actualDirectory = (info.Attributes & NativeMethods.DirectoryAttribute) != 0;
      if (actualDirectory != directory || (info.Attributes & NativeMethods.ReparseAttribute) != 0)
        throw new InvalidDataException("Owned parent handle type is invalid");
      if (oneLink && info.Links != 1)
        throw new InvalidDataException("Owned parent marker is multiply linked");
      Identity identity = new Identity();
      identity.Volume = info.VolumeSerial;
      identity.High = info.IndexHigh;
      identity.Low = info.IndexLow;
      return identity;
    }

    void CheckIdentity(SafeFileHandle handle, Identity expected, bool directory, bool oneLink) {
      Identity actual = ValidateHandle(handle, directory, oneLink);
      if (actual.Volume != expected.Volume || actual.High != expected.High ||
          actual.Low != expected.Low)
        throw new InvalidDataException("Owned parent handle identity changed");
    }

    static byte[] ReadHandle(SafeFileHandle handle, int expectedLength) {
      long size;
      if (!NativeMethods.GetFileSizeEx(handle, out size) || size != expectedLength)
        throw new InvalidDataException("Owned parent marker size is invalid");
      long position;
      if (!NativeMethods.SetFilePointerEx(handle, 0, out position, 0))
        throw new Win32Exception(Marshal.GetLastWin32Error());
      byte[] bytes = new byte[expectedLength];
      int read;
      if (!NativeMethods.ReadFile(handle, bytes, bytes.Length, out read, IntPtr.Zero) ||
          read != bytes.Length) throw new Win32Exception(Marshal.GetLastWin32Error());
      return bytes;
    }

    static void AssertBytes(byte[] actual, byte[] expected) {
      if (actual.Length != expected.Length)
        throw new InvalidDataException("Owned parent marker is malformed");
      for (int index = 0; index < actual.Length; ++index)
        if (actual[index] != expected[index])
          throw new InvalidDataException("Owned parent marker is malformed");
    }

    void EnsureActive() {
      if (disposed || marker == null || marker.IsInvalid || sourceMarker == null ||
          sourceMarker.IsInvalid || generatedMarker == null || generatedMarker.IsInvalid ||
          directories.Count == 0)
        throw new ObjectDisposedException("OwnedParentSession");
    }

    void RollbackCreated() {
      if (createdMarker) MarkDeleteNoThrow(marker);
      if (createdParent) MarkDeleteNoThrow(publicationDirectory);
    }

    static void MarkDeleteNoThrow(SafeFileHandle handle) {
      if (handle == null || handle.IsInvalid) return;
      IntPtr buffer = Marshal.AllocHGlobal(4);
      try {
        Marshal.WriteInt32(buffer, 1);
        NativeMethods.SetFileInformationByHandle(handle, 4, buffer, 4);
      } finally {
        Marshal.FreeHGlobal(buffer);
      }
    }

    public void Dispose() {
      if (disposed) return;
      disposed = true;
      if (marker != null) marker.Dispose();
      if (generatedMarker != null) generatedMarker.Dispose();
      if (sourceMarker != null) sourceMarker.Dispose();
      for (int index = directories.Count - 1; index >= 0; --index)
        directories[index].Dispose();
      directories.Clear();
      directoryIdentities.Clear();
    }
  }

  public sealed class OwnedLeafSession : IDisposable {
    struct Identity {
      internal uint Volume;
      internal uint High;
      internal uint Low;
    }

    readonly string parentPath;
    readonly string temporaryName;
    readonly string markerName;
    readonly byte[] markerBytes;
    readonly HashSet<string> allowed;
    readonly Dictionary<string, byte[]> expectedHashes = new Dictionary<string, byte[]>(
      StringComparer.Ordinal);
    readonly int maximumFileBytes;
    readonly int maximumTotalBytes;
    readonly List<SafeFileHandle> chain = new List<SafeFileHandle>();
    OwnedParentSession retainedParent;
    SafeFileHandle directory;
    SafeFileHandle marker;
    Identity directoryIdentity;
    Identity markerIdentity;
    bool completed;

#if FAULTLOOM_TRANSACTION_TEST_HOOK
    public static Action TestAfterTemporaryDirectoryCreated;
#endif

    OwnedLeafSession(string parent, string name, byte[] bytes, string[] names,
        int fileLimit, int totalLimit) {
      parentPath = parent;
      temporaryName = name;
      markerName = "." + name + ".faultloom-owned-v1";
      markerBytes = (byte[])bytes.Clone();
      allowed = new HashSet<string>(names, StringComparer.Ordinal);
      maximumFileBytes = fileLimit;
      maximumTotalBytes = totalLimit;
    }

    SafeFileHandle Parent {
      get { return retainedParent == null ? chain[chain.Count - 1] : retainedParent.Directory; }
    }

    static void ValidateArguments(string temporaryName, byte[] markerBytes,
        string[] allowedNames, int maximumFileBytes, int maximumTotalBytes) {
      if (temporaryName == null || markerBytes == null || allowedNames == null)
        throw new ArgumentNullException();
      if (!System.Text.RegularExpressions.Regex.IsMatch(temporaryName,
          @"^\.(package|smoke)-[0-9a-f]{32}$"))
        throw new ArgumentException("Temporary leaf name is invalid");
      if (allowedNames.Length == 0 || maximumFileBytes <= 0 ||
          maximumTotalBytes < maximumFileBytes)
        throw new ArgumentException("Owned leaf limits are invalid");
      HashSet<string> checkedNames = new HashSet<string>(StringComparer.Ordinal);
      foreach (string name in allowedNames) {
        if (name == null || !System.Text.RegularExpressions.Regex.IsMatch(name,
            @"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$") || !checkedNames.Add(name))
          throw new ArgumentException("Owned leaf member name is invalid");
      }
    }

    public static OwnedLeafSession Create(string repositoryPath, string parentPath,
        string temporaryName, byte[] markerBytes, string[] allowedNames,
        int maximumFileBytes, int maximumTotalBytes) {
      if (repositoryPath == null || parentPath == null) throw new ArgumentNullException();
      ValidateArguments(temporaryName, markerBytes, allowedNames, maximumFileBytes,
        maximumTotalBytes);
      string repository = Path.GetFullPath(repositoryPath).TrimEnd(Path.DirectorySeparatorChar);
      string parent = Path.GetFullPath(parentPath).TrimEnd(Path.DirectorySeparatorChar);
      if (!parent.Equals(repository, StringComparison.OrdinalIgnoreCase) &&
          !parent.StartsWith(repository + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase))
        throw new ArgumentException("Owned leaf parent escapes the repository");
      OwnedLeafSession session = new OwnedLeafSession(parent, temporaryName, markerBytes,
        allowedNames, maximumFileBytes, maximumTotalBytes);
      try {
        session.OpenChain(repository, parent);
        return session.CreateTemporary();
      } catch {
        session.DisposeChain();
        throw;
      }
    }

    public static OwnedLeafSession Create(OwnedParentSession parentSession,
        string temporaryName, byte[] markerBytes, string[] allowedNames,
        int maximumFileBytes, int maximumTotalBytes) {
      if (parentSession == null) throw new ArgumentNullException("parentSession");
      ValidateArguments(temporaryName, markerBytes, allowedNames, maximumFileBytes,
        maximumTotalBytes);
      parentSession.Validate();
      OwnedLeafSession session = new OwnedLeafSession(parentSession.PathValue, temporaryName,
        markerBytes, allowedNames, maximumFileBytes, maximumTotalBytes);
      session.retainedParent = parentSession;
      return session.CreateTemporary();
    }

    OwnedLeafSession CreateTemporary() {
      try {
        if (retainedParent != null) retainedParent.Validate();
        directory = NativeMethods.OpenRelative(Parent, temporaryName,
          NativeMethods.Delete | NativeMethods.ListDirectory | NativeMethods.ReadAttributes |
            NativeMethods.Synchronize,
          NativeMethods.FileCreate,
          NativeMethods.DirectoryFile | NativeMethods.SynchronousIo |
            NativeMethods.OpenReparsePoint);
#if FAULTLOOM_TRANSACTION_TEST_HOOK
        Action hook = TestAfterTemporaryDirectoryCreated;
        TestAfterTemporaryDirectoryCreated = null;
        if (hook != null) hook();
#endif
        directoryIdentity = ValidatePath(directory,
          Path.Combine(parentPath, temporaryName), true, false);
        marker = NativeMethods.OpenRelative(Parent, markerName,
          NativeMethods.Delete | NativeMethods.ReadData | NativeMethods.WriteData |
            NativeMethods.ReadAttributes | NativeMethods.Synchronize,
          NativeMethods.FileCreate,
          NativeMethods.NonDirectoryFile | NativeMethods.SynchronousIo |
            NativeMethods.OpenReparsePoint);
        WriteHandle(marker, markerBytes);
        markerIdentity = ValidatePath(marker,
          Path.Combine(parentPath, markerName), false, true);
        return this;
      } catch {
        try {
          if (marker != null && !marker.IsClosed && !marker.IsInvalid) {
            try { MarkDelete(marker); } finally { marker.Dispose(); }
          }
        } finally {
          try {
            if (directory != null && !directory.IsClosed && !directory.IsInvalid) {
              try { MarkDelete(directory); } finally { directory.Dispose(); }
            }
          } finally {
            if (retainedParent == null) DisposeChain();
          }
        }
        throw;
      }
    }

    void OpenChain(string repository, string parent) {
      string current = repository;
      SafeFileHandle root = NativeMethods.OpenDirectory(current,
        current.Equals(parent, StringComparison.OrdinalIgnoreCase));
      ValidatePath(root, current, true, false);
      chain.Add(root);
      if (current.Equals(parent, StringComparison.OrdinalIgnoreCase)) return;
      string relative = parent.Substring(repository.Length).TrimStart(Path.DirectorySeparatorChar);
      string[] parts = relative.Split(Path.DirectorySeparatorChar);
      for (int index = 0; index < parts.Length; ++index) {
        current = Path.Combine(current, parts[index]);
        SafeFileHandle handle = NativeMethods.OpenDirectory(current, index == parts.Length - 1);
        try {
          ValidatePath(handle, current, true, false);
          chain.Add(handle);
        } catch {
          handle.Dispose();
          throw;
        }
      }
    }

    public void WriteMember(string name, byte[] bytes) {
      EnsureActive();
      if (!allowed.Contains(name) || bytes == null || bytes.Length > maximumFileBytes)
        throw new ArgumentException("Owned leaf member is invalid");
      CheckIdentity(directory, directoryIdentity, true, false);
      SafeFileHandle member = null;
      try {
        member = NativeMethods.OpenRelative(directory, name,
          NativeMethods.Delete | NativeMethods.ReadData | NativeMethods.WriteData |
            NativeMethods.ReadAttributes | NativeMethods.Synchronize,
          NativeMethods.FileCreate,
          NativeMethods.NonDirectoryFile | NativeMethods.SynchronousIo |
            NativeMethods.OpenReparsePoint);
        WriteHandle(member, bytes);
        ValidateHandle(member, false, true);
        using (System.Security.Cryptography.SHA256 algorithm =
            System.Security.Cryptography.SHA256.Create()) {
          expectedHashes.Add(name, algorithm.ComputeHash(bytes));
        }
      } catch {
        if (member != null && !member.IsInvalid) MarkDelete(member);
        throw;
      } finally {
        if (member != null) member.Dispose();
      }
    }

    public byte[] ReadMember(string name) {
      EnsureActive();
      if (!allowed.Contains(name)) throw new ArgumentException("Owned leaf member is invalid");
      CheckIdentity(directory, directoryIdentity, true, false);
      using (SafeFileHandle member = NativeMethods.OpenRelative(directory, name,
          NativeMethods.ReadData | NativeMethods.ReadAttributes | NativeMethods.Synchronize,
          NativeMethods.FileOpen,
          NativeMethods.NonDirectoryFile | NativeMethods.SynchronousIo |
            NativeMethods.OpenReparsePoint)) {
        ValidateHandle(member, false, true);
        return ReadHandle(member, maximumFileBytes);
      }
    }

    public void Validate(bool requireComplete) {
      List<SafeFileHandle> members = AcquireMembers(requireComplete);
      foreach (SafeFileHandle member in members) member.Dispose();
    }

    public void Publish(string outputName, byte[] expectedMarker) {
      EnsureActive();
      if (outputName == null || !System.Text.RegularExpressions.Regex.IsMatch(outputName,
          @"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"))
        throw new ArgumentException("Output leaf name is invalid");
      AssertBytes(expectedMarker, markerBytes);
      List<SafeFileHandle> members = AcquireMembers(true);
      foreach (SafeFileHandle member in members) member.Dispose();
      members.Clear();
      SafeFileHandle finalMarker = null;
      try {
        string finalMarkerName = "." + outputName + ".faultloom-owned-v1";
        finalMarker = NativeMethods.OpenRelative(Parent, finalMarkerName,
          NativeMethods.Delete | NativeMethods.ReadData | NativeMethods.WriteData |
            NativeMethods.ReadAttributes | NativeMethods.Synchronize,
          NativeMethods.FileCreate,
          NativeMethods.NonDirectoryFile | NativeMethods.SynchronousIo |
            NativeMethods.OpenReparsePoint);
        WriteHandle(finalMarker, markerBytes);
        ValidatePath(finalMarker, Path.Combine(parentPath, finalMarkerName), false, true);
        NativeMethods.RenameRelative(directory, Parent, outputName);
        List<SafeFileHandle> publishedMembers = AcquireMembers(true);
        foreach (SafeFileHandle member in publishedMembers) member.Dispose();
        CheckIdentity(marker, markerIdentity, false, true);
        MarkDelete(marker);
        marker.Dispose();
        directory.Dispose();
        finalMarker.Dispose();
        DisposeChain();
        completed = true;
      } catch {
        if (finalMarker != null && !finalMarker.IsInvalid) {
          MarkDelete(finalMarker);
          finalMarker.Dispose();
        }
        throw;
      } finally {
        foreach (SafeFileHandle member in members) member.Dispose();
      }
    }

    public void Cleanup() {
      EnsureActive();
      List<SafeFileHandle> members = AcquireMembers(false);
      try {
        foreach (SafeFileHandle member in members) MarkDelete(member);
      } finally {
        foreach (SafeFileHandle member in members) member.Dispose();
      }
      CheckIdentity(directory, directoryIdentity, true, false);
      CheckIdentity(marker, markerIdentity, false, true);
      MarkDelete(directory);
      MarkDelete(marker);
      directory.Dispose();
      marker.Dispose();
      DisposeChain();
      completed = true;
    }

    List<SafeFileHandle> AcquireMembers(bool requireComplete) {
      EnsureActive();
      CheckIdentity(directory, directoryIdentity, true, false);
      CheckIdentity(marker, markerIdentity, false, true);
      AssertBytes(ReadHandle(marker, maximumFileBytes), markerBytes);
      List<string> names = NativeMethods.ListNames(directory, allowed.Count);
      if (requireComplete && names.Count != allowed.Count)
        throw new InvalidDataException("Temporary leaf is incomplete");
      List<SafeFileHandle> handles = new List<SafeFileHandle>();
      long total = 0;
      try {
        foreach (string name in names) {
          if (!allowed.Contains(name)) throw new InvalidDataException("Temporary leaf has a foreign member");
          SafeFileHandle handle = NativeMethods.OpenRelative(directory, name,
            NativeMethods.Delete | NativeMethods.ReadData | NativeMethods.ReadAttributes |
              NativeMethods.Synchronize,
            NativeMethods.FileOpen,
            NativeMethods.NonDirectoryFile | NativeMethods.SynchronousIo |
              NativeMethods.OpenReparsePoint);
          ValidateHandle(handle, false, true);
          long size;
          if (!NativeMethods.GetFileSizeEx(handle, out size))
            throw new Win32Exception(Marshal.GetLastWin32Error());
          if (size > maximumFileBytes) throw new InvalidDataException("Temporary member exceeds its limit");
          byte[] expectedHash;
          if (!expectedHashes.TryGetValue(name, out expectedHash))
            throw new InvalidDataException("Temporary member was not written by this session");
          byte[] memberBytes = ReadHandle(handle, maximumFileBytes);
          using (System.Security.Cryptography.SHA256 algorithm =
              System.Security.Cryptography.SHA256.Create()) {
            AssertBytes(algorithm.ComputeHash(memberBytes), expectedHash);
          }
          total += size;
          handles.Add(handle);
        }
        if (total > maximumTotalBytes) throw new InvalidDataException("Temporary leaf exceeds its limit");
        if (requireComplete) {
          foreach (string name in allowed)
            if (!names.Exists(delegate(string value) { return value == name; }))
              throw new InvalidDataException("Temporary leaf is incomplete");
        }
        return handles;
      } catch {
        foreach (SafeFileHandle handle in handles) handle.Dispose();
        throw;
      }
    }

    Identity ValidatePath(SafeFileHandle handle, string expected, bool expectDirectory, bool oneLink) {
      if (!NativeMethods.FinalPath(handle).Equals(Path.GetFullPath(expected),
          StringComparison.OrdinalIgnoreCase))
        throw new InvalidDataException("Owned leaf path canonical mismatch");
      return ValidateHandle(handle, expectDirectory, oneLink);
    }

    Identity ValidateHandle(SafeFileHandle handle, bool expectDirectory, bool oneLink) {
      NativeMethods.FileInformation info;
      if (!NativeMethods.GetFileInformationByHandle(handle, out info))
        throw new Win32Exception(Marshal.GetLastWin32Error());
      bool isDirectory = (info.Attributes & NativeMethods.DirectoryAttribute) != 0;
      if (isDirectory != expectDirectory || (info.Attributes & NativeMethods.ReparseAttribute) != 0)
        throw new InvalidDataException("Owned leaf handle type is invalid");
      if (oneLink && info.Links != 1) throw new InvalidDataException("Owned leaf handle is multiply linked");
      Identity identity = new Identity();
      identity.Volume = info.VolumeSerial;
      identity.High = info.IndexHigh;
      identity.Low = info.IndexLow;
      return identity;
    }

    void CheckIdentity(SafeFileHandle handle, Identity expected, bool directoryValue, bool oneLink) {
      Identity actual = ValidateHandle(handle, directoryValue, oneLink);
      if (actual.Volume != expected.Volume || actual.High != expected.High || actual.Low != expected.Low)
        throw new InvalidDataException("Owned leaf handle identity changed");
    }

    void MarkDelete(SafeFileHandle handle) {
      IntPtr buffer = Marshal.AllocHGlobal(4);
      try {
        Marshal.WriteInt32(buffer, 1);
        if (!NativeMethods.SetFileInformationByHandle(handle, 4, buffer, 4))
          throw new Win32Exception(Marshal.GetLastWin32Error());
      } finally {
        Marshal.FreeHGlobal(buffer);
      }
    }

    void WriteHandle(SafeFileHandle handle, byte[] bytes) {
      int written;
      if (!NativeMethods.WriteFile(handle, bytes, bytes.Length, out written, IntPtr.Zero) ||
          written != bytes.Length) throw new Win32Exception(Marshal.GetLastWin32Error());
      if (!NativeMethods.FlushFileBuffers(handle))
        throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    byte[] ReadHandle(SafeFileHandle handle, int limit) {
      long size;
      if (!NativeMethods.GetFileSizeEx(handle, out size) || size < 0 || size > limit)
        throw new InvalidDataException("Owned leaf member size is invalid");
      long position;
      if (!NativeMethods.SetFilePointerEx(handle, 0, out position, 0))
        throw new Win32Exception(Marshal.GetLastWin32Error());
      byte[] bytes = new byte[(int)size];
      int read;
      if (!NativeMethods.ReadFile(handle, bytes, bytes.Length, out read, IntPtr.Zero) ||
          read != bytes.Length) throw new Win32Exception(Marshal.GetLastWin32Error());
      return bytes;
    }

    static void AssertBytes(byte[] actual, byte[] expected) {
      if (actual == null || expected == null || actual.Length != expected.Length)
        throw new InvalidDataException("Owned leaf marker is malformed");
      for (int index = 0; index < actual.Length; ++index)
        if (actual[index] != expected[index])
          throw new InvalidDataException("Owned leaf marker is malformed");
    }

    void EnsureActive() {
      if (completed || directory == null || marker == null ||
          (retainedParent == null && chain.Count == 0))
        throw new InvalidOperationException("Owned leaf session is not active");
      if (retainedParent != null) retainedParent.Validate();
    }

    void DisposeChain() {
      for (int index = chain.Count - 1; index >= 0; --index) chain[index].Dispose();
      chain.Clear();
    }

    public void Dispose() {
      if (marker != null) marker.Dispose();
      if (directory != null) directory.Dispose();
      DisposeChain();
    }
  }
}
