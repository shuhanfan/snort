package snort.test.Helpers;

public class Http {
	private int length;
	private int count;
	private String src_ip;
	private String dst_ip;
	
	public Http(){}
	public Http(int length,int count,String src_ip,String dst_ip)
	{
		this.length=length;
		this.count=count;
		this.src_ip=src_ip;
		this.dst_ip=dst_ip;
	}
	public void Setlength(int length)
	{
		this.length=this.length+length;
	}
	public int Getlength()
	{
		return this.length;
	}
	public void Setcount(int count)
	{
		this.count=this.count+count;
	}
	public int Getcount()
	{
		return this.count;
	}
	public String Getsrc_ip()
	{
		return src_ip;	
	}
	public String Getdst_ip()
	{
		return dst_ip;	
	}
	public void Setsrc_ip(String src_ip)
	{
		this.src_ip=src_ip;	
	}
	public void Setdst_ip(String dst_ip)
	{
		this.dst_ip=dst_ip;	
	}
	public void Inithttp()
	{
		this.length=0;
		this.count=0;
		this.src_ip=null;
		this.dst_ip=null;
	}
}
