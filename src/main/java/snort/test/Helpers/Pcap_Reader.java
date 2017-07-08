package snort.test.Helpers;



public class Pcap_Reader {
	public int ip_type=0;//ip类型
	public String transfer_type="";//传输层类型
	
	public Pcap_header pcap_header;
	public Ether ether;
	public Ipv6 ipv6;
	public Tcp tcp;
	public Udp udp;
	public String payload=null;
	
	public Pcap_Reader()
	{
		pcap_header = new Pcap_header();
		ether = new Ether();
		ipv6 = new Ipv6();
		tcp = new Tcp();
		udp = new Udp();
	}
	
	public class Pcap_header{
		public long time_s=0;//时间戳（秒）
		public long time_ms=0;//时间戳（微秒）
		public int pLength=0;//抓包长度
		public int length=0;//实际长度
		public void pcap_header_reader(byte[] header)
		{
			byte[] time_s_byte=new byte[4];
			byte[] time_ms_byte=new byte[4];
			byte[] pLength_byte=new byte[4];
			byte[] length_byte=new byte[4];
			for(int i=0;i<4;i++){
				time_s_byte[i]=header[3-i];
				time_ms_byte[i]=header[7-i];
				pLength_byte[i]=header[11-i];
				length_byte[i]=header[15-i];
			}
				
				time_s=BytetoLong(time_s_byte,4);
				time_ms=BytetoLong(time_ms_byte,4);
				pLength=BytetoInt(pLength_byte,4);
				length=BytetoInt(length_byte,4);
		}
			
	}
	public class Ether{
		public String ether_dhost=null;//目的mac地址
		public String ether_shost=null;//源mac地址
		public int ether_type=0;//以太网类型
	}
	
	public class Ipv6{
		public int version=0;//版本
		public int traffic_class=0;//通信量类
		public int flow_label=0;//流标号
		public int payload_length=0;//有效载荷长度
		public int next_header=0;//下一个首部
		public int hop_limit=0;//跳数限制
		public String src=null;//源ip地址
		public String dst=null;//目的ip地址
		
	};
	public class Tcp{
		public int src_port=0;//源端口
		public int dst_port=0;//目的端口
		public long number=0;//序号
		public long confirm_number=0;//确认号
		public int data_offset=0;//数据偏移
		public int remain=0;//保留
		public boolean URG=false;//紧急URG
		public boolean ACK=false;//确认ACK
		public boolean PSH=false;//推送PSH
		public boolean RST=false;//复位RST;
		public boolean SYN=false;//同步SYN
		public boolean FIN=false;//终止FIN
		public int window=0;//窗口
		public int checksum=0;//检验和
		public int urgent_pointer=0;//紧急指针
		public String option=null;//选项
		public int fill=0;//填充
	};
	public class Udp{
		public int src_port=0;
		public int dst_port=0;
		public int length=0;
		public int checksum=0;
	};
	public void data_read(byte[] data,int length)
	{
		byte[] src_mac_byte=new byte[6];
		byte[] dst_mac_byte=new byte[6];
		byte[] ether_type_byte=new byte[2];
		for(int i=0;i<6;i++){
			src_mac_byte[i]=data[i];
			dst_mac_byte[i]=data[6+i];
		}
		ether_type_byte[0]=data[12];
		ether_type_byte[1]=data[13];
		ether.ether_shost=MACBytetoString(src_mac_byte,6);
		ether.ether_dhost=MACBytetoString(dst_mac_byte,6);
		ether.ether_type=BytetoInt(ether_type_byte,2);
		
		/*
		System.out.println("ether.ether_shost:"+ether.ether_shost);
		System.out.println("ether.ether_dhost:"+ether.ether_dhost);
		System.out.println("ether.ether_type:"+ether.ether_type);
		*/
		if(ether.ether_type==0x86DD){
			byte[] ipv6_byte=new byte[40];
			for(int i=0;i<40;i++)
			{
				ipv6_byte[i]=data[14+i];
			}
			ipv6.version=(ipv6_byte[0]&0xf0)/16;
			ipv6.traffic_class=(ipv6_byte[0]&0x0f)*16+(ipv6_byte[1]&0xf0)/16;
			ipv6.flow_label=(ipv6_byte[1]&0x0f)*16*16*16+(ipv6_byte[2]&0xff)*16*16+(ipv6_byte[3]&0xff);
			ipv6.payload_length=(ipv6_byte[4]&0xff)*16*16+(ipv6_byte[5]&0xff);
			ipv6.next_header=(ipv6_byte[6]&0xff);
			ipv6.hop_limit=(ipv6_byte[7]&0xff);
			byte[] src_byte=new byte[16];
			byte[] dst_byte=new byte[16];
			for(int i=0;i<16;i++){
				src_byte[i]=ipv6_byte[8+i];
				dst_byte[i]=ipv6_byte[8+16+i];
			}
			ipv6.src=IPBytetoString(src_byte,16);
			ipv6.dst=IPBytetoString(dst_byte,16);
			/*
			System.out.println("ipv6.version:"+ipv6.version);
			System.out.println("ipv6.traffic_class:"+ipv6.traffic_class);
			System.out.println("ipv6.flow_label:"+ipv6.flow_label);
			System.out.println("ipv6.payload_length:"+ipv6.payload_length);
			System.out.println("ipv6.next_header:"+ipv6.next_header);
			System.out.println("ipv6.hop_limit:"+ipv6.hop_limit);
			System.out.println("ipv6.src:"+ipv6.src);
			System.out.println("ipv6.dst:"+ipv6.dst);
			*/
			
			if(ipv6.next_header==6){
				byte[] tcp_byte=new byte[20];
				for(int i=0;i<tcp_byte.length;i++){
					tcp_byte[i]=data[14+40+i];
				}
				tcp.src_port=(tcp_byte[0]&0xff)*16*16+(tcp_byte[1]&0xff);
				tcp.dst_port=(tcp_byte[2]&0xff)*16*16+(tcp_byte[3]&0xff);
				byte[] number_byte=new byte[4];
				byte[] confirm_number_byte=new byte[4];
				for(int i=0;i<4;i++){
					number_byte[i]=tcp_byte[4+i];
					confirm_number_byte[i]=tcp_byte[8+i];
				}
				tcp.number=BytetoLong(number_byte,4);
				tcp.confirm_number=BytetoLong(confirm_number_byte,4);
				tcp.data_offset=(tcp_byte[12]&0xf0)/16;
				tcp.remain=(tcp_byte[12]&0x0f)*4+(tcp_byte[13]&0x90)/64;
				tcp.URG=(tcp_byte[13]&0x20)==0x20;
				tcp.ACK=(tcp_byte[13]&0x10)==0x10;
				tcp.PSH=(tcp_byte[13]&0x08)==0x08;
				tcp.RST=(tcp_byte[13]&0x04)==0x04;
				tcp.SYN=(tcp_byte[13]&0x02)==0x02;
				tcp.FIN=(tcp_byte[13]&0x01)==0x01;
			    tcp.window=(tcp_byte[14]&0xff)*16*16+(tcp_byte[15]&0xff);
			    tcp.checksum=(tcp_byte[16]&0xff)*16*16+(tcp_byte[17]&0xff);
			    tcp.urgent_pointer=(tcp_byte[18]&0xff)*16*16+(tcp_byte[19]&0xff);
			    transfer_type="tcp";
			    if(length-14-40-20!=0){
			    	byte[] payload_byte=new byte[length-14-40-20];
			    	for(int i=0;i<payload_byte.length;i++){
			    		payload_byte[i]=data[14+40+20+i];
			    	}
			    	payload=BytetoString(payload_byte,payload_byte.length);
			    }
			    /*
			    System.out.println("tcp.src_port:"+tcp.src_port);
			    System.out.println("tcp.dst_port:"+tcp.dst_port);
			    System.out.println("tcp.number:"+tcp.number);
			    System.out.println("tcp.confirm_number:"+tcp.confirm_number);
			    System.out.println("tcp.data_offset:"+tcp.data_offset);
			    System.out.println("tcp.remain:"+tcp.remain);
			    System.out.println("tcp.URG:"+tcp.URG);
			    System.out.println("tcp.ACK:"+tcp.ACK);
			    System.out.println("tcp.PSH:"+tcp.PSH);
			    System.out.println("tcp.RST:"+tcp.RST);
			    System.out.println("tcp.SYN:"+tcp.SYN);
			    System.out.println("tcp.FIN:"+tcp.FIN);
			    System.out.println("tcp.window:"+ tcp.window);
			    System.out.println("tcp.checksum:"+tcp.checksum);
			    System.out.println("tcp.urgent_pointer:"+tcp.urgent_pointer);
			    System.out.println("tranfer_type:"+tranfer_type);
			    */
			    
			}
			if(ipv6.next_header==17){
				byte[] udp_byte=new byte[8];
				for(int i=0;i<udp_byte.length;i++){
					udp_byte[i]=data[14+40+i];
				}
				
				udp.src_port=(udp_byte[0]&0xff)*16*16+(udp_byte[1]&0xff);
				udp.dst_port=(udp_byte[2]&0xff)*16*16+(udp_byte[3]&0xff);
				udp.length=(udp_byte[4]&0xff)*16*16+(udp_byte[5]&0xff);
				udp.checksum=(udp_byte[6]&0xff)*16*16+(udp_byte[7]&0xff);
				transfer_type="udp";
				if(length-14-40-8!=0){
			    	byte[] payload_byte=new byte[length-14-40-8];
			    	for(int i=0;i<payload_byte.length;i++){
			    		payload_byte[i]=data[14+40+8+i];
			    	}
			    	payload=BytetoString(payload_byte,payload_byte.length);
			    }
				/*
				System.out.println("udp.src_port:"+udp.src_port);
				System.out.println("udp.dst_port:"+udp.dst_port);
				System.out.println("udp.length:"+udp.length);
				System.out.println("udp.checksum:"+udp.checksum);
				*/
			}
		}
		
		
	}
	public void read(byte[] pcap_buf,int length){
		
		byte[] header=new byte[16];
		byte[] data=new byte[length-16];
		
		for(int i=0;i<16;i++){
			header[i]=pcap_buf[i];
		}
		
		
		for (int i=0;i<data.length;i++){
			data[i]=pcap_buf[16+i];
		}
		
		this.pcap_header.pcap_header_reader(header);
		this.data_read(data, data.length);
	}
	
	public long BytetoLong (byte[] a,int length)
	{
		long cer=0;
		for(int i=0;i<length;i++)
		{
			cer=cer*16*16;
			cer=cer+(a[i]&0xff);
		}
		return cer;
	}
	
	public int BytetoInt (byte[] a,int length)
	{
		int cer=0;
		for(int i=0;i<length;i++)
		{
			cer=cer*16*16;
			cer=cer+(a[i]&0xff);
		}
		return cer;
	}
	public String IPBytetoString (byte[] a,int length)
	{
		String cer="";
		for(int i=0;i<length;i++)
		{
			String hex=Integer.toHexString(a[i] & 0xFF);
			if(hex.length()==1){
        		hex ='0'+hex;
        	}
			if(i%2==1&&i!=length-1){
			cer=cer+hex+":";
			}else{
				cer=cer+hex;
			}
		}
		return cer;
	}
	public String MACBytetoString (byte[] a,int length)
	{
		String cer="";
		for(int i=0;i<length;i++)
		{
			String hex=Integer.toHexString(a[i] & 0xFF);
			if(hex.length()==1){
        		hex ='0'+hex;
        	}
			if(i!=length-1){
			cer=cer+hex+":";
			}else{
				cer=cer+hex;
			}
		}
		return cer;
	}
	public String BytetoString (byte[] a,int length)
	{
		String cer="";
		for(int i=0;i<length;i++)
		{
			String hex=Integer.toHexString(a[i] & 0xFF);
			if(hex.length()==1){
        		hex ='0'+hex;
        	}
				cer=cer+hex;

		}
		return cer;
	}

}
