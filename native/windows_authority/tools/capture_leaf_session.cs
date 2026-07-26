namespace FaultLoom.Capture {
  public sealed partial class CaptureLeafSession : IDisposable {
    struct Identity {
      internal uint Volume;
      internal uint High;
      internal uint Low;
    }

    readonly string baselinePath;
    readonly string leafName;
    readonly string markerName;
    readonly byte[] markerBytes;
    SafeFileHandle baseline;
    SafeFileHandle directory;
    SafeFileHandle marker;
    Identity directoryIdentity;
    Identity markerIdentity;
    bool completed;

    CaptureLeafSession(string path, string name, byte[] bytes) {
      baselinePath = path;
      leafName = name;
      markerName = "." + name + ".faultloom-owned-v1";
      markerBytes = (byte[])bytes.Clone();
    }

    public static CaptureLeafSession Create(string baselinePath, string leafName, byte[] markerBytes) {
      if (baselinePath == null || leafName == null || markerBytes == null)
        throw new ArgumentNullException();
      if (!System.Text.RegularExpressions.Regex.IsMatch(leafName, @"^\.capture-[0-9a-f]{32}$"))
        throw new ArgumentException("Temporary leaf name is invalid");
      string root = Path.GetFullPath(baselinePath).TrimEnd(Path.DirectorySeparatorChar);
      CaptureLeafSession session = new CaptureLeafSession(root, leafName, markerBytes);
      try {
        session.baseline = NativeMethods.OpenBaseline(root);
        session.ValidatePath(session.baseline, root, true, false);
        session.directory = NativeMethods.OpenRelative(session.baseline, leafName,
          NativeMethods.Delete | NativeMethods.ListDirectory | NativeMethods.ReadAttributes | NativeMethods.Synchronize,
          NativeMethods.FileCreate,
          NativeMethods.DirectoryFile | NativeMethods.SynchronousIo | NativeMethods.OpenReparsePoint);
        session.directoryIdentity = session.ValidatePath(session.directory,
          Path.Combine(root, leafName), true, false);
        try {
          session.marker = NativeMethods.OpenRelative(session.baseline, session.markerName,
            NativeMethods.Delete | NativeMethods.ReadData | NativeMethods.WriteData |
              NativeMethods.ReadAttributes | NativeMethods.Synchronize,
            NativeMethods.FileCreate,
            NativeMethods.NonDirectoryFile | NativeMethods.SynchronousIo | NativeMethods.OpenReparsePoint);
          session.WriteHandle(session.marker, markerBytes);
          session.markerIdentity = session.ValidatePath(session.marker,
            Path.Combine(root, session.markerName), false, true);
        } catch {
          if (session.marker != null && !session.marker.IsInvalid) {
            session.MarkDelete(session.marker);
            session.marker.Dispose();
          }
          session.MarkDelete(session.directory);
          session.directory.Dispose();
          throw;
        }
        return session;
      } catch {
        if (session.baseline != null) session.baseline.Dispose();
        throw;
      }
    }

    public void WriteMember(string name, byte[] bytes) {
      EnsureActive();
      if (!IsAllowed(name) || bytes == null || bytes.Length > 262144)
        throw new ArgumentException("Capture member is invalid");
      CheckIdentity(directory, directoryIdentity, true, false);
      SafeFileHandle member = null;
      try {
        member = NativeMethods.OpenRelative(directory, name,
          NativeMethods.Delete | NativeMethods.ReadData | NativeMethods.WriteData |
            NativeMethods.ReadAttributes | NativeMethods.Synchronize,
          NativeMethods.FileCreate,
          NativeMethods.NonDirectoryFile | NativeMethods.SynchronousIo | NativeMethods.OpenReparsePoint);
        WriteHandle(member, bytes);
        ValidateHandle(member, false, true);
      } catch {
        if (member != null && !member.IsInvalid) MarkDelete(member);
        throw;
      } finally {
        if (member != null) member.Dispose();
      }
    }

    public void Validate(bool requireComplete) {
      List<SafeFileHandle> members = AcquireMembers(requireComplete);
      foreach (SafeFileHandle member in members) member.Dispose();
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
      baseline.Dispose();
      completed = true;
    }

    public void Publish(string outputName, byte[] expectedMarker) {
      EnsureActive();
      if (outputName == null || !System.Text.RegularExpressions.Regex.IsMatch(outputName, @"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"))
        throw new ArgumentException("Output leaf name is invalid");
      AssertBytes(expectedMarker, markerBytes);
      List<SafeFileHandle> members = AcquireMembers(true);
      foreach (SafeFileHandle member in members) member.Dispose();
      members.Clear();
      SafeFileHandle finalMarker = null;
      try {
        string finalMarkerName = "." + outputName + ".faultloom-owned-v1";
        finalMarker = NativeMethods.OpenRelative(baseline, finalMarkerName,
          NativeMethods.Delete | NativeMethods.ReadData | NativeMethods.WriteData |
            NativeMethods.ReadAttributes | NativeMethods.Synchronize,
          NativeMethods.FileCreate,
          NativeMethods.NonDirectoryFile | NativeMethods.SynchronousIo | NativeMethods.OpenReparsePoint);
        WriteHandle(finalMarker, markerBytes);
        ValidatePath(finalMarker, Path.Combine(baselinePath, finalMarkerName), false, true);
        NativeMethods.RenameRelative(directory, baseline, outputName);
        CheckIdentity(marker, markerIdentity, false, true);
        MarkDelete(marker);
        marker.Dispose();
        directory.Dispose();
        finalMarker.Dispose();
        baseline.Dispose();
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

    List<SafeFileHandle> AcquireMembers(bool requireComplete) {
      EnsureActive();
      CheckIdentity(directory, directoryIdentity, true, false);
      CheckIdentity(marker, markerIdentity, false, true);
      AssertBytes(ReadHandle(marker), markerBytes);
      List<string> names = NativeMethods.ListNames(directory, 3);
      if (requireComplete && names.Count != 3) throw new InvalidDataException("Temporary leaf is incomplete");
      List<SafeFileHandle> handles = new List<SafeFileHandle>();
      long total = 0;
      try {
        foreach (string name in names) {
          if (!IsAllowed(name)) throw new InvalidDataException("Temporary leaf has a foreign member");
          SafeFileHandle handle = NativeMethods.OpenRelative(directory, name,
            NativeMethods.Delete | NativeMethods.ReadData | NativeMethods.ReadAttributes | NativeMethods.Synchronize,
            NativeMethods.FileOpen,
            NativeMethods.NonDirectoryFile | NativeMethods.SynchronousIo | NativeMethods.OpenReparsePoint);
          ValidateHandle(handle, false, true);
          long size;
          if (!NativeMethods.GetFileSizeEx(handle, out size)) throw new Win32Exception(Marshal.GetLastWin32Error());
          if (size > 262144) throw new InvalidDataException("Temporary member exceeds 256 KiB");
          total += size;
          handles.Add(handle);
        }
        if (total > 1048576) throw new InvalidDataException("Temporary leaf exceeds 1 MiB");
        if (requireComplete) {
          foreach (string allowed in new[] { "host.json", "services.json", "baseline.sha256" })
            if (!names.Exists(delegate(string value) { return value == allowed; }))
              throw new InvalidDataException("Temporary leaf is incomplete");
        }
        return handles;
      } catch {
        foreach (SafeFileHandle handle in handles) handle.Dispose();
        throw;
      }
    }

  }
}
