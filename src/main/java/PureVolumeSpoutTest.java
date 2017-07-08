import java.util.ArrayList;
import java.util.List;
import snort.test.Helpers.CreateValue;
import org.jnetpcap.Pcap;
//提供一个各种库方法到java的直接映射：发现网络接口
import org.jnetpcap.PcapIf;
//把地址模拟为链式的地址结构
import org.jnetpcap.packet.PcapPacket; 
import org.jnetpcap.packet.PcapPacketHandler;
//一个处理、监听、回调的接口，用于在一个新的packet捕获的时候，获得通知
public class PureVolumeSpoutTest {
	public long lastTime;
	public long curTime ;
	public long period;
	public PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {  
		 
        public void nextPacket(PcapPacket packet, String user) {  
        	curTime = System.nanoTime();
        	period = curTime - lastTime;
        	System.out.println("get packet period:" + period );
        	lastTime = curTime;
            
        }  
    };
	public  void main(String[] args) {
		List<PcapIf> alldevs = new ArrayList<PcapIf>();
		
		//alldevs用来装载所有的network interface card
		StringBuilder errbuf = new StringBuilder();
		//获取错误信息
		int r = Pcap.findAllDevs(alldevs, errbuf);
		//获取系统中的设备列表
		
		if(r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Cant read list of devices, error is: %s",errbuf.toString());
			return;
		}
		
		System.out.println("Network devices found:");
		
		//选择需要的网卡
		int i = 0;
		int chooseid = 0;
		for(PcapIf device : alldevs) {
			if("eth1".equals(device.getName())) {
				chooseid = i;
				break;
			}
			i++;
		}
		
		PcapIf device = alldevs.get(chooseid);
		
		//打开我们选中的设备
		int snaplen = 64 * 1024;
		//捕获包的最大长度，如果比该值大，则被截断
		//不截断地捕获所有的包
		int flags = Pcap.MODE_PROMISCUOUS;
		//capture all packets
		int timeout = 10 * 1000;
		//10seconds in millis
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
		//打开一个和指定网络设备有关的，活跃的捕获器
		if(pcap == null) {
			System.err.printf("Error while opening device for capture:%s", errbuf.toString());
			return;
		}
//		CreateValue cv = new CreateValue();
//		pcap.loop(-1, cv, "jnetpcap");  
//        pcap.close();
        /*************************************************************************** 
        
         * 第三步我们创建一个packet handler 处理器来从libpcap loop中接收数据包
         **************************************************************************/ 
         
 
        /*************************************************************************** 
         * Fourth we enter the loop and tell it to capture 10 packets. The loop 
         * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which 
         * is needed by JScanner. The scanner scans the packet buffer and decodes 
         * the headers. The mapping is done automatically, although a variation on 
         * the loop method exists that allows the programmer to sepecify exactly 
         * which protocol ID to use as the data link type for this pcap interface. 
         * 第四步，将handler进入loop中并告诉它抓取10个包，其它的等以后熟悉了api使用在看看是什么意思
         **************************************************************************/ 
        pcap.loop(-1, jpacketHandler, "jNetPcap rocks!");  
 
        /*************************************************************************** 
         * 最后一定要关闭pcap，否则抛出异常
         **************************************************************************/ 
        pcap.close();  
    }  
	
	 
	

}
