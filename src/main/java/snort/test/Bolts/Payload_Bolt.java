package snort.test.Bolts;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

import backtype.storm.task.OutputCollector;
import backtype.storm.task.TopologyContext;
import backtype.storm.topology.BasicOutputCollector;
import backtype.storm.topology.FailedException;
import backtype.storm.topology.IBasicBolt;
import backtype.storm.topology.OutputFieldsDeclarer;
import backtype.storm.tuple.Fields;
import backtype.storm.tuple.Tuple;
import backtype.storm.tuple.Values;

import java.io.*; 

import snort.test.Helpers.Packet_Header;
import snort.test.Helpers.Rule_Header;
import snort.test.Helpers.DealOption;
import snort.test.Helpers.RuleOption;


public class Payload_Bolt implements IBasicBolt{

	private BasicOutputCollector outputCollector;
	private ArrayList<Rule_Header> rule_set;
	private int packnum =0;
	private int detect = 0;
	private long pktlen = 0;//record the transport flow
	private boolean transfer = false;
	private long curTime = 0;
	private long lastTime = 0;
	private long duringTime = 0;
	public Payload_Bolt(){
		
	}
	public void declareOutputFields(OutputFieldsDeclarer declarer) {
		// TODO Auto-generated method stub
		declarer.declare(new Fields("time", "packnum", "detect", "flow"));
	}

	public Map<String, Object> getComponentConfiguration() {
		// TODO Auto-generated method stub
		return null;
	}

//	}
	public void prepare(Map stormConf, TopologyContext context) {
		packnum = 0;
		rule_set = new ArrayList<Rule_Header>(500);
		lastTime = System.currentTimeMillis()/1000;	
	}

	public void execute(Tuple tuple, BasicOutputCollector collector) {
		// TODO Auto-generated method stub
		outputCollector = collector;
		outputCollector.setContext(tuple);  
		String name=tuple.getSourceStreamId();  
		try {
			//改为固定1s向ResultBolt发送包
			
			curTime = System.currentTimeMillis()/1000;
			duringTime = curTime-lastTime;
			if(duringTime > 0) {
				this.outputCollector.emit(new Values(curTime, packnum, detect, pktlen));
			    pktlen = 0;
			    packnum = 0;
			    detect = 0;
			    lastTime = curTime;
    		 }		
			if(name.equals("payload")){
				if (!transfer)
					return;	
				Packet_Header pcaket_tmp =new Packet_Header();
				pcaket_tmp.payload=(byte[])tuple.getValueByField("payload");
				pcaket_tmp.ack = (Long)tuple.getValueByField("ack");
				pcaket_tmp.DF = (Integer)tuple.getValueByField("DF");
				pcaket_tmp.dsize = (Integer)tuple.getValueByField("dsize");
				pcaket_tmp.ip_proto = (Integer)tuple.getValueByField("ip_proto");
				pcaket_tmp.Reserved= (Integer)tuple.getValueByField("Reserved");
				pcaket_tmp.fragoffset = (Integer)tuple.getValueByField("fragoffset");
				pcaket_tmp.ttl = (Integer)tuple.getValueByField("ttl");
				pcaket_tmp.tos = (Integer)tuple.getValueByField("tos");
				pcaket_tmp.id = (Integer)tuple.getValueByField("id");
				pcaket_tmp.flags = (Integer)tuple.getValueByField("flags");
				pcaket_tmp.seq = (Long)tuple.getValueByField("seq");
				pcaket_tmp.window = (Integer)tuple.getValueByField("window");
				pcaket_tmp.sameip = (Boolean) tuple.getValueByField("sameip");
				pktlen += (Integer)tuple.getValueByField("total_len");

				//规则选项处理逻辑接口
				
				int rule_number = (Integer)tuple.getValueByField("ruleNumber");
				Rule_Header rule_header = rule_set.get(rule_number);
				DealOption dealOption = new DealOption(pcaket_tmp, rule_header.parsed_rule_option);
				detect += dealOption.run();
				packnum++;
			}
			else if(name.equals("rule") )
			{				
				
				transfer = (Boolean)tuple.getValueByField("switch");
				if(transfer) {
					return;
				}
				Rule_Header rule_tmp = new Rule_Header();
				rule_tmp.action=(String)tuple.getValueByField("action");
				rule_tmp.protocol=(String)tuple.getValueByField("protocol");
				rule_tmp.sip=(String)tuple.getValueByField("sip");
				rule_tmp.sport=(String)tuple.getValueByField("sport");
				rule_tmp.direction=(String)tuple.getValueByField("direction");
				rule_tmp.dip=(String)tuple.getValueByField("dip");
				rule_tmp.dport=(String)tuple.getValueByField("dport");
				rule_tmp.rule_option=(ArrayList)tuple.getValueByField("option");
				//get parsed_rule_option
				rule_tmp.parsed_rule_option = parseRuleOption(rule_tmp.rule_option);
				rule_set.add(rule_tmp);						
			}
		} catch(FailedException e) {
	    	System.out.println("in payloadBolt"+e.getMessage());
	    } 
	}
	
	public static boolean isIgnore(String s) {
		 if(s.equals(" classtype")||s.equals(" metadata")||s.equals(" rev")||s.equals(" sid")||s.equals(" gid")||s.equals(" priority")||s.equals(" reference")||s.equals(" logto")||s.equals(" session")||s.equals(" resp")||s.equals(" react")||s.equals(" tag")||s.equals(" activates")||s.equals(" activated_by")||s.equals(" count")||s.equals(" replace")||s.equals(" detection_filter"))
			 return true;
		 return false;
		
	}
	
	public String BytetoHexString (byte[] a,int length)
	{
		String cer="";
		for(int i=0;i<length;i++)
		{
			String hex=Integer.toHexString(a[i]&0xFF);
			if(hex.length()==1){
        		hex ='0'+hex;
        	}		
				cer=cer+hex;		
		}
		return cer;
	}
	
	public static ArrayList<RuleOption> parseRuleOption(ArrayList<String> rule_option) {
		ArrayList<RuleOption> res = new ArrayList<RuleOption>(100);
		int rule_option_size = rule_option.size();
		for(int i=0 ; i<rule_option_size; i++) {
			RuleOption ro = new RuleOption();//新建一个规则选项类
			String option = (String)rule_option.get(i);
			
			int pos = option.indexOf("content");
			String noncontent = option;
			String content = "none";
			if(pos != -1) {//存在content选项
				noncontent = option.substring(0, pos);
				content = option.substring(pos, option.length());
			}
			
			//解析noncontent
			String[] field = noncontent.split(";");
			//存储最后的警告信息
			String msg = field[0].split(":")[1];
			ro.headMap.put(" msg", msg);
			for(int j=1; j<field.length-1;j++){
				 if(field[j].equals(""))
					 break;
				 String k = field[j].split(":")[0];
				 if(!isIgnore(k)){
					 String val = "";
					 if(field[j].split(":").length>1)
						 val =field[j].split(":")[1];
					 ro.headMap.put(k, val);
				 }
			 }
			
			//ro.headMap存储了content字段之前的内容
			 if(content.equals("none")) {
				 res.add(ro);
				 continue;
			 }
			 
			 //进行content以及以后的内容构建
			 String[] con = content.split("content");
			 int con_len = con.length;
			 for(int j = 1; j < con_len; j++) {
				 Map<String, String> aContent = new LinkedHashMap<String, String>(50);
				 String[] block = con[j].split(";");
				 
				 int block_len = block.length;
				 for (int k = 0; k < block_len - 1; k++) {
					 String first = block[k].split(":")[0];
					 if(!isIgnore(first)){
						 String second ="";
						 if(block[k].split(":").length>1)
							  second =block[k].split(":")[1];			
						 if(first.equals("")){
							 aContent.put(" content", second);
						 }
						 else{
							 aContent.put(first,second);
						 }
					 }
				 }//对一个content内的选项进行创建
				 ro.conMap.add(aContent);
			 }//创建一个option内的所有content
			res.add(ro); 
		}//创建完所有rule头相等的选项数组
		return res;	
	}

	public void cleanup() {
		// TODO Auto-generated method stub
		
	}

}
