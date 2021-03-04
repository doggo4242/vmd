namespace vmd{
	public class AsmExec{
		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		private delegate void runAsm();

		[DllImport("kernel32.dll")]
		private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
		public static void asmExec(byte[] asm){
			unsafe
        	{
				fixed (byte* ptr = asm)
            	{
					var memoryAddress = (IntPtr) ptr;

					// Mark memory as EXECUTE_READWRITE to prevent DEP exceptions
					if (!VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress, (UIntPtr) assembledCode.Length, 0x40 /* EXECUTE_READWRITE */, out uint _))
					{
						throw new Win32Exception();
					}

					var asmFunc = Marshal.GetDelegateForFunctionPointer<runAsm>(memoryAddress);
					asmFunc();
				}               
			}
		}
	}
}
