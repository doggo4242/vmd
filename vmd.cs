namespace vmd{
	public class detect{
		// TODO: add anti-debugger measures
		public bool vmd_vmdetect(){
			ulong t0,t1;
			t0=Rdtscp.getRdtscp();
			byte[] asm = {0x0F, 0xA2};
			AsmExec.asmExec(asm);
			t1=Rdtscp.getRdtscp();
			long cpuid_time = t1-t0;
			t0=Rdtscp.getRdtscp();
			asm = new byte[]{0xDF, 0x35, 0x00, 0x00, 0x00, 0x00, 0xC3};
			AsmExec.asmExec(asm);
			t1=Rdtscp.getRdtscp();
			long fbstp_time = t1-t0;
			return (fbstp_time>=cpuid_time);
		}
		public bool vmd_hardwaresus(){
			if(Environment.ProcessorCount < 2){
				return true;
			}
			ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher(new ObjectQuery("SELECT * FROM Win32_OperatingSystem");
			if(int.Parse(managementObjectSearcher.Get().OfType<ManagementObject>().FirstOrDefault()["TotalVisibleMemorySize"].ToString()) < 1.074e6){
				return true;
			}
			var uptime = new PerformanceCounter("System", "System Up Time");
			uptime.nextValue();
			if(uptime.nextValue() < (5*60)){
				return true;
			}
			var searcher = new ManagementObjectSearcher(@"select * from Win32_DiskDrive");
			return (int.Parse(searcher.Get().OfType<ManagementObject>().FirstOrDefault()["Size"].ToString()) <= 6.442e10);	
		}
		public bool vmd_incontainer(){
			return (Process.getCurrentProcess().Id < 250);
		}
	}
}
