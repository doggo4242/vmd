namespace vmd{
	public class Rdtscp{
		const uint PAGE_EXECUTE_READWRITE = 0x40;
		const uint MEM_COMMIT = 0x1000;
	
		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
		
		private static IntPtr Alloc(byte[] asm)
		{
		    var ptr = VirtualAlloc(IntPtr.Zero, (uint)asm.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		    Marshal.Copy(asm, 0, ptr, asm.Length);
		    return ptr;
		}
		
		delegate long RdtscpDelegate();
		
		static readonly byte[] rdtscpAsm =
		{
		    0x0F, 0x01, 0xF9, // rdtscp
		    0xC3        // ret
		};
		public static ulong getRdtscp(){
			var rdtscp = Marshal.GetDelegateForFunctionPointer<RdtscpDelegate>(Alloc(rdtscpAsm));
			return rdtscp();
		}
	}
}
