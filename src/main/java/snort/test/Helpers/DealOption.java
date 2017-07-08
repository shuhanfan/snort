package snort.test.Helpers;

import java.io.FileWriter;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
 * Depth = 5;表示就在前5个byte里面搜索
offset = 5； 表示忽略前5byte
Distance = 5；表示在前一个匹配结尾处，忽略5个byte
within= 5表示在前一个匹配结尾处的之后5个byte之间匹配
 * */
 
public class DealOption {
	public Packet_Header ph;
	public ArrayList<RuleOption > parsed_rules;//解析后的规则选项列表
	int detect = 0;
	public DealOption(){}
	
	public DealOption(Packet_Header this_ph) {
		ph = this_ph;
		
	}
	
	public DealOption(Packet_Header this_ph, ArrayList<RuleOption> this_parsed_rules){
	    ph = this_ph;
		parsed_rules = this_parsed_rules;		
	}
	 
	public static String BytetoHexString (byte[] a,int length) {//将byte数组转化为16进制字符串
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
	 
	 public static void get_next(String par,int next[]){
		int i=0;
		next[0]=-1;
		int j=-1;
		if(par.equals(" "))
			return;
		int par_len = par.length();
		for(;i<par_len;){
			if(j==-1||par.charAt(i)==par.charAt(j)){
				i++;
				j++;
				if(i<par_len){
					if(par.charAt(i)==par.charAt(j)) next[i]=next[j];
					else next[i]=j; 
				}			
			}
			else
				j=next[j];
		}
	}

	 
	public static boolean IndexKMP(String ori, String par, int nk,Map<Integer,ArrayList<Integer> > res,boolean isStr,boolean ignoreCase, boolean negative) {
	    int i=0;
		int j=0;
		int st = i;
		if(par.equals(" ")) ignoreCase = false;
		int par_len = par.length();
		int amount = 0;
		ArrayList<Integer> v = new ArrayList<Integer>(50);
		int[] next = new int[par_len];
		get_next(par,next);
		while(i<ori.length()){
			if(j==-1||ori.charAt(i)==par.charAt(j) || isStr&&ignoreCase &&String.valueOf(par.charAt(j)).toUpperCase().equals(String.valueOf(par.charAt(j)).toUpperCase())) {
				i++;
				j++;
			}
			else j=next[j];	
			if(j==par_len) {		
				amount++;
				if(isStr){				
					v.add((i-j)*2);
				}	
				else {//以byte为记录偏移的单位				
					v.add((i-j));
				}				
				i=i-j+1;
				j=0;		
			}
		} 
		res.put(nk, v);
		if(!negative) {
			if(amount==0) return false;
			return true;		
		}
		else {
			if(amount==0) return true;
			return false;
		}	 
	 }
	 
	 public static int KMP(String value,byte[] payload,int nk,Map<Integer,ArrayList<Integer> > res, boolean ignoreCase) {//value是匹配的原串
	 try{
		int pattern_len = 0;
		 String oris;
		 boolean negative = false;
		 boolean isString = false;
		 if("".equals(value) || value == null)
			 return 0;
		 if(value.charAt(1)=='!') {
			 negative = true;
			 value = value.substring(2,value.length()-1);
		 }
		 else {
			 value = value.substring(1, value.length()-1);
		 }
		 byte[] app = new byte[payload.length];		 
		 //选出原串和匹配串		 
		 String[] pat = value.split("\\|");//一定是 str+byte+str
		 oris = new String(payload,"utf-8");
		 		
		 String orib = BytetoHexString(payload,payload.length);//orib的长度是oris的两倍
		 //如果含有byte模式串，进行kmp算法匹配，否则是正常匹配		 
		 if(pat.length == 1){//只有字符串匹配
			 isString = true;
			 pattern_len = value.length()*2;
			 if(IndexKMP(oris,pat[0],nk,res,isString,ignoreCase,negative))
				 return pattern_len;
			 else 
				 return 0;		
		 }
		 else if(pat.length == 2 && ("").equals(pat[0])){//只有二进制匹配
			 pat[1]=pat[1].replace(" ", "");
			 pattern_len = pat[1].length();
			 if(IndexKMP(orib,pat[1],nk,res,isString,ignoreCase,negative))
				 return pattern_len;
			 else 
				 return 0;		 
		 }
		else{
			pat[1] = pat[1].replace(" ", "");
			
			if(IndexKMP(orib,pat[1],nk,res,isString,ignoreCase,negative)){
				int newstart = -1;
				int cur_len = 0;
				ArrayList<Integer> re = res.get(nk);//re是第nk个content匹配的位置集
				for(int i=0; i<re.size(); ){					 
					 cur_len = pat[1].length();
					 newstart = re.get(i) + pat[1].length();
					 if(!pat[0].equals("")){
						cur_len += pat[0].length()*2;
						 if(re.get(i)-pat[0].length()*2>=0){
							 String tmp = oris.substring(re.get(i)/2-pat[0].length(),re.get(i)/2);
							 if(tmp.equals(pat[0])){
								 re.set(i,re.get(i)-pat[0].length()*2);
							 }
							 else{
								 re.remove(i);
								 if(re.size() == 0){
									 return 0;
								 }									 
								 continue;								 
							 }													 
						 }
						 else{
							 re.remove(i);
							 if(re.size() == 0){
								 return 0;
							 }
							 continue;
						 }
						 
					 }
					 int j = 2;
					 for(; j<pat.length; j++){
						 String p = pat[j];
						 
						 if(j%2==1){//match byte
							 p = p.replace(" ", "");
							 cur_len += p.length();
							 if(newstart+p.length()>orib.length()){
								 re.remove(i);
								 if(re.size() == 0){
									 return 0;
								 }
									 
								 break;
							 }
							 String tmp = orib.substring(newstart, newstart+p.length());
							 if(!tmp.equals(p)){
								 re.remove(i);
								 if(re.size() == 0){
									 return 0;
								 }
									 
								 break;
							 }
							 else{
								 newstart += p.length();
							 }
						 }
						 else{//match string						 
							 cur_len += p.length()*2;
							 if(newstart+p.length()*2>orib.length()){
								 re.remove(i);
								 if(re.size() == 0){
									 return 0;
								 }									 
								 break;
							 }
							 String tmp = oris.substring(newstart/2, newstart/2+p.length());
							 if(ignoreCase) {
								 tmp = tmp.toLowerCase();
								 p = p.toLowerCase();
							 }
							 if(!tmp.equals(p)){
								 re.remove(i);
								 if(re.size() == 0){
									 return 0;
								 }									 
								 break;
							 }
							 else{
								 newstart += p.length() * 2;
							 }
							 
						 }
						 
					 }
					 
					 if(j == pat.length) {//the par str match success so check the next , or else because of break and remove a offset,so not need i++ when check the next matc
						 i++;	
						 
					 }
					 if(cur_len > pattern_len)
						 pattern_len = cur_len;
					 
					 
				 }
				 if(re.size()==0) return 0;
				return pattern_len;
				 
			 }
			else{
				return 0;
			}		
		 }	 
	} catch (UnsupportedEncodingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	return 1;
	 }
 
	 public void Detect(RuleOption ro, byte[] payload){
			 for ( int n = 0 ; n <ro.conMap.size(); n++){
				 Map<String, String> map = ro.conMap.get(n); 
				 
			 }
			for(Iterator it = ro.headMap.keySet().iterator(); it.hasNext();) {
				 String  key=it.next().toString();    
			     String value=ro.headMap.get(key);
			     if(key.equals(" fragoffset")){
			    	 if(value.contains("!")) {
			    		 if(ph.fragoffset == Integer.parseInt(value.substring(1))){			 
			    			 return;

			    		 }
			    			 
			    	 }
			    	 else if(value.contains(">")) {
			    		 if (ph.fragoffset <= Integer.parseInt(value.substring(1)) ){
			    			 return;
			    		 }
			    			 
			    	 }
			    	 else if(value.contains("<")) {
			    		 if(ph.fragoffset >= Integer.parseInt(value.substring(1))){
			    			 return;
			    		 }
			    			 
			    	 }
			    	 else if (ph.fragoffset != Integer.parseInt(value)){
			    		 return;
			    	 }
			    		 
			     }
			     else if (key.equals(" ttl")) {
			    	 if(value.contains("<=")) {
			    		 if(ph.ttl > Integer.parseInt(value.substring(2))){
			    			 return;
			    		 }
			    				    		 
			    	 }
			    	 else if(value.contains(">=")) {
			    		 if(ph.ttl < Integer.parseInt(value.substring(2))){
			    			 return;
			    		 }
			    			 	 
			    	 }
			    	 else if(value.contains("<")) {
			    		 if(ph.ttl >= Integer.parseInt(value.substring(1))){
			    			 return;
			    		 }
			    				    		 
			    	 }
			    	 else if(value.contains(">")) {
			    		 if(ph.ttl <= Integer.parseInt(value.substring(1))){
			    			 return;
			    		 }
			    				    		 
			    	 }
			    	 else if(value.contains("=")) {
			    		 if(ph.ttl != Integer.parseInt(value.substring(1))){
			    			 return;
			    		 }
			    			 	    		 
			    	 }
			    	 else if( value.contains("-")) {
			    		 String[] vals = value.split("-");
		    			 if(vals.length == 1) {// 5-
		    				 if(ph.ttl < Integer.parseInt(value.substring(0, 1))){
		    					 return;
		    				 }
				    			 
		    			 }
		    			 else {//lenth = 2
		    				 if("".equals(vals[0])) {//-5
		    					 if(ph.ttl > Integer.parseInt(vals[1])){
		    						 return;
		    					 }
		    							    					 
		    				 }
		    				 else {//3-5
		    					 if(ph.ttl < Integer.parseInt(vals[0]) || ph.ttl > Integer.parseInt(vals[1])){
		    						 return;
		    					 }
		    						 
		    				 }		    				 
		    			 }			    		 			    		 
			    	 }
			    	 else {//5
			    		 if(ph.ttl != Integer.parseInt(value)){
			    			 return;
			    		 }
			    						    		 
			    	 }
			     }
			     else if(key.equals(" tos")) {
			    	 if(value.contains("!")) {
			    		 if(ph.tos == Integer.parseInt(value.substring(1))){
			    			 return;
			    		 }	    		 
			    	 }
			    	 else if(!value.equals(ph.tos+"")){
			    		 return;
			    	 }
			    		
			     }
			     else if(key.equals(" id")) {
			    	 if(!value.equals(ph.id+"")){
			    		 return;
			    	 }
			    		 
			     }
			     
			     else if(key.equals(" fragbits")){//format is <MDR+>
			    	 if(value.contains("!")){
			    		 if(value.contains("M")&&ph.MF==1){
			    			 return;
			    		 }
			    			 
			    		 if(value.contains("R")&&ph.Reserved==1){
			    			 return;
			    		 }
			    			 
			    		 if(value.contains("D")&&ph.DF==1){
			    			 return;
			    		 }
			    			 
			    	 }
			    	 else if(value.contains("*")){
			    		 if(!(value.contains("M")&&ph.MF==1||value.contains("D")&&ph.DF==1||value.contains("R")&&ph.Reserved==1)){
			    			 return;
			    		 }
			    			
			    	 }
			    	 else if(value.contains("+")){
			    		 if((value.contains("M")&&ph.MF!=1||value.contains("D")&&ph. DF!=1||value.contains("R")&&ph. Reserved!=1)) {
			    			 return;
			    		 }
			    			 
			    	 }
			     }
			     else if (key.equals(" ip_proto")){
			    	 String pro = Integer.toString(ph.ip_proto);
			    	 if(!value.equals(pro)){
			    		 return;
			    	 }
			    		
			    	 
			     }
			     
			     else if(key.equals(" dsize")){
			    	 int dsize = ph.dsize;
			    	 String size = Integer.toString(dsize);
			    	 if(!value.equals(size)){
			    		 if(value.contains("<>")) {
			    			 String[] d = value.split("<>");
			    			 int min = Integer.parseInt(d[0]);
			    			 int max = Integer.parseInt(d[1]);
			    			 if(dsize>max || dsize<min) {
					    		 return;
			    			 }
			    		 }
			    		 else if(value.contains(">")) {
			    			 int min = Integer.parseInt(value.substring(1));
			    			 if( dsize<min) {
					    		 return;
			    			 }
			    		 }
			    		 else if(value.contains("<")) {
			    			 int max = Integer.parseInt(value.substring(1));
			    			 if( dsize>max) {
					    		 return;
			    			 }
			    		 }
			    		 else{
				    		 return;
			    		 }
			    	 }
			    		 
			    	 
			     }
			     else if(key.equals(" flags")){//CEUAPRSF,可以用12表示CE
			    	 if(value.contains(",")) {
			    		 value = value.split(",")[0];
			    	 }
			    	 //先解析出为true的字符
			    	 int flags = ph.flags;
			    	 String a = "";
			    	 boolean F = false;
			    	 boolean S = false;
			    	 boolean R = false;
			    	 boolean P = false;
			    	 boolean A = false;
			    	 boolean U = false;
			    	 boolean E = false;
			    	 boolean C = false;
			    	 if((flags & 1) == 1) F = true;
			    	 if((flags & 2)>>1 == 1) S = true;
			    	 if((flags & 4)>>2 == 1) R = true;
			    	 if((flags & 8)>>3 == 1) P = true;
			    	 if((flags & 16)>>4 == 1) A = true;
			    	 if((flags & 32)>>5 == 1) U = true;
			    	 if((flags & 64)>>6 == 1) E = true;
			    	 if((flags & 128)>>7 == 1) C = true;
			    	
			    	 if(value.contains("!")){
			    		 if(value.contains("F")&&F) {
			    			 return;
			    		 }
			    			 
			    		 if(value.contains("S")&&S) {
			    			 return;
			    		 }
			    			
			    		 if(value.contains("R")&&R) {
			    			 return;
			    		 }
			    			 
			    		 if(value.contains("P")&&P) {
			    			 return;
			    		 }
			    			 
			    		 if(value.contains("A")&&A) {
			    			 return;
			    		 }
			    			
			    		 if(value.contains("U")&&U) {
			    			 return;
			    		 }
			    			 
			    		 if((value.contains("E") || value.contains("2"))&&E) {
			    			 return;
			    		 }
			    			
			    		 if((value.contains("C")|| value.contains("1"))&&C) {
			    			 return;
			    		 }
			    			
			    	 }
			    	 else if(value.contains("*")) {
			    		 if(!(value.contains("F")&&F || value.contains("S")&&S || value.contains("R")&&R || value.contains("P")&&P || value.contains("A")&&A || value.contains("U")&&U || (value.contains("E")||value.contains("2"))&&E || (value.contains("C") || value.contains("1"))&&C )) {			    			
			    			 return;
			    		 }
			    			
			    	 }
			    	 else if(value.contains("+")) {
			    		 if((value.contains("F")&&!F || value.contains("S")&&!S || value.contains("R")&&!R || value.contains("P")&&!P || value.contains("A")&&!A || value.contains("U")&&!U || (value.contains("E")||value.contains("2"))&&!E || (value.contains("C") || value.contains("1"))&&!C )) {
			    			 return;
			    		 }			    			
			    	 }			    			    	 
			     }
			     else if(key.equals(" seq")) {
			    	 if(!value.equals(ph.seq+"")) {
			    		 return;
			    	 }			    		    	 
			     }
			     else if(key.equals(" ack")){
			    	 if(!value.equals(ph.ack+"")) {
			    		 return;
			    	 }			    	 
			     }
			     else if(key.equals(" window")){
			    	 if(value.contains("!")) {
			    		 if(ph.window == Integer.parseInt(value.substring(1))){
			    			 return;
			    		 }	    		 
			    	 }
			    	 else if(!value.equals(ph.window+"")){
			    		 return;
			    	 }			    	 
			     }
			     else if(key.equals(" sameip")) {
			    	 if(!ph.sameip) {
			    		 return;
			    	 }			    			    	 
			     }	     
			 }
						
			//payload相关字段进行检测
			Map<Integer,ArrayList<Integer> > res;
			 res = new HashMap<Integer,ArrayList<Integer> > (20);
			 int ro_conMap_size = ro.conMap.size();
			for(int k=0; k<ro_conMap_size; k++){
				int pattern_len = 0;
				Map<String,String> tmp = ro.conMap.get(k);//每个tmp都是一个content和modifier小分队集合
				//表示存入的结果集的key		
				boolean ignoreCase = false;
				if(tmp.containsKey(" nocase")){
					ignoreCase = true;
				}
				String value=tmp.get(" content");
				pattern_len = KMP(value,payload,k,res,ignoreCase);
				if(pattern_len == 0) {
					//res存储的是第k个content的匹配所有匹配位置，k表示匹配的是第k个content
					 return;
				}
				ro.conMap.get(k).put("pattern_len", Integer.toString(pattern_len));			 
			}		
			//检验content modifier的值
			for(int k=0; k<ro.conMap.size(); k++){
				Map<String,String> tmp = ro.conMap.get(k);//每个tmp都是一个content和modifier小分队集合
				ArrayList<Integer> mat = ( ArrayList<Integer>) res.get(k);//每个option中一个content的匹配结果
				int nk = 1;
				int within = 0;
				int offset = 0;
				int depth = 0;
				int distance = 0;
				int pattern_len = 0;
			
				String pattern = tmp.get(" content");				
				if(tmp.containsKey(" within"))
					within = Integer.parseInt(tmp.get(" within"));
				if(tmp.containsKey(" depth"))
					depth = Integer.parseInt(tmp.get(" depth"));
				if(tmp.containsKey(" distance"))
					distance = Integer.parseInt(tmp.get(" distance"));
				if(tmp.containsKey(" offset"))
					offset = Integer.parseInt(tmp.get(" offset"));
				pattern_len = Integer.parseInt(tmp.get("pattern_len"));
				for(int h=0; h<mat.size(); )	{
					int pos = mat.get(h);				
					//注意pos是从0开始算的，但是offset是从1开始的
					if(pos>=offset&&(depth == 0 ||(pos+pattern_len<=depth+offset))) {
					    boolean isOk = false;
					    ArrayList<Integer> lastmat;
					  //检测该content匹配位置是否满足distance
						if(distance!=0 && k>0){
							lastmat = (ArrayList<Integer>) res.get(k-1);
							int lastmat_size = lastmat.size();
							for(int j=0; j<lastmat_size; j++){
								if(lastmat.get(j)+distance<pos){
									isOk=true;	
									break;
								}									
							}
							if(!isOk){
								mat.remove(h);
								if(mat.size()==0) {
									return;
								}									
								continue;
							}																					
						}
						//检测该content匹配位置是否满足within
						isOk=false;
						if(within!=0 && k>0){
							lastmat = ( ArrayList<Integer>) res.get(k-1);
							int lastmat_size = lastmat.size();
							for(int j=0; j<lastmat_size; j++){
								if(lastmat.get(j)+distance+within>=pos+pattern_len-1){
									isOk=true;	
									break;
								}
																	
							}
							if(!isOk){
								mat.remove(h);
								if(mat.size()==0) {
								}									
								continue;								
							}								
						}						
						//检测该匹配位置是否满足isdataat						
						if(tmp.containsKey(" isdataat")) {
							String value = tmp.get(" isdataat");							
							if(!value.contains("!")){
								String[] vals = value.split(",");
								int far = Integer.parseInt(vals[0]);
								if(vals.length > 1 && vals[1].equals("relative")){
									if(payload.length < pos+pattern.length()+far) {
										mat.remove(h);
										if(mat.size()==0) {
											return;
										}
											
										continue;
									}
									
								}
								else {
									if(payload.length < far) {
										mat.remove(h);
										if(mat.size()==0) {
											return;
										}										
										continue;
									}
								}
							}							
							else{//isdataat:!2,relative
								String[] vals = value.substring(1).split(",");
								int far = Integer.parseInt(vals[0]);
								if(vals.length > 1 && vals[2].equals("relative")){
									if(payload.length >= pos+pattern.length()+far) {
										mat.remove(h);
										if(mat.size()==0) {
											return;
										}											
										continue;
									}									
								}
								else {
									if(payload.length > far) {
										mat.remove(h);
										if(mat.size()==0) {
											return;
										}
										continue;
									}
								}															
							}
						}										
						//检测该匹配位置是否需要为下一个设置pk_data
						if(tmp.containsKey(" pkt_data")) {
							mat.set(h, 0);
						}			
						else{
							mat.set(h, pos+pattern_len-1);
						}
						//将匹配起始值更新为匹配终止值
						h++;						
					}
					else {
						return ;
					}
				   break;
				}			
			}
			detect++;	 
		
	 }
	
	public int run(){
		for(int i=0; i<parsed_rules.size(); i++){//遍历规则选项链表，检测数据包
			RuleOption ro =parsed_rules.get(i);
			Detect(ro, ph.payload);			
		}
		return detect;		
	}
}
