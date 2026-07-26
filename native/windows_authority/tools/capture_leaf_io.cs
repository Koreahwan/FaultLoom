namespace FaultLoom.Capture {
  public sealed partial class CaptureLeafSession {
    Identity ValidatePath(SafeFileHandle handle, string expected, bool expectDirectory, bool oneLink) {
      if (!NativeMethods.FinalPath(handle).Equals(Path.GetFullPath(expected), StringComparison.OrdinalIgnoreCase))
        throw new InvalidDataException("Capture path canonical mismatch");
      return ValidateHandle(handle, expectDirectory, oneLink);
    }

    Identity ValidateHandle(SafeFileHandle handle, bool expectDirectory, bool oneLink) {
      NativeMethods.FileInformation info;
      if (!NativeMethods.GetFileInformationByHandle(handle, out info))
        throw new Win32Exception(Marshal.GetLastWin32Error());
      bool directoryValue = (info.Attributes & NativeMethods.DirectoryAttribute) != 0;
      if (directoryValue != expectDirectory || (info.Attributes & NativeMethods.ReparseAttribute) != 0)
        throw new InvalidDataException("Capture handle type is invalid");
      if (oneLink && info.Links != 1) throw new InvalidDataException("Capture handle is multiply linked");
      Identity identity = new Identity();
      identity.Volume = info.VolumeSerial;
      identity.High = info.IndexHigh;
      identity.Low = info.IndexLow;
      return identity;
    }

    void CheckIdentity(SafeFileHandle handle, Identity expected, bool directoryValue, bool oneLink) {
      Identity actual = ValidateHandle(handle, directoryValue, oneLink);
      if (actual.Volume != expected.Volume || actual.High != expected.High || actual.Low != expected.Low)
        throw new InvalidDataException("Capture handle identity changed");
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
      if (!NativeMethods.WriteFile(handle, bytes, bytes.Length, out written, IntPtr.Zero) || written != bytes.Length)
        throw new Win32Exception(Marshal.GetLastWin32Error());
      if (!NativeMethods.FlushFileBuffers(handle)) throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    byte[] ReadHandle(SafeFileHandle handle) {
      long size;
      if (!NativeMethods.GetFileSizeEx(handle, out size) || size > 262144)
        throw new InvalidDataException("Capture marker size is invalid");
      long position;
      if (!NativeMethods.SetFilePointerEx(handle, 0, out position, 0))
        throw new Win32Exception(Marshal.GetLastWin32Error());
      byte[] bytes = new byte[(int)size];
      int read;
      if (!NativeMethods.ReadFile(handle, bytes, bytes.Length, out read, IntPtr.Zero) || read != bytes.Length)
        throw new Win32Exception(Marshal.GetLastWin32Error());
      return bytes;
    }

    static void AssertBytes(byte[] actual, byte[] expected) {
      if (actual == null || expected == null || actual.Length != expected.Length)
        throw new InvalidDataException("Capture marker is malformed");
      for (int index = 0; index < actual.Length; ++index)
        if (actual[index] != expected[index]) throw new InvalidDataException("Capture marker is malformed");
    }

    static bool IsAllowed(string name) {
      return name == "host.json" || name == "services.json" || name == "baseline.sha256";
    }

    void EnsureActive() {
      if (completed || baseline == null || directory == null || marker == null)
        throw new InvalidOperationException("Capture leaf session is not active");
    }

    public void Dispose() {
      if (marker != null) marker.Dispose();
      if (directory != null) directory.Dispose();
      if (baseline != null) baseline.Dispose();
    }
  }
}
