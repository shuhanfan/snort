import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import snort.test.Helpers.RuleOption;
import snort.test.Helpers.Rule_Header;
import snort.test.Spouts.Rule_Spout;
public class RuleFilter {
	//for test rule filter
	public static void main(String args[]) {
		try{
			FileInputStream fis = new FileInputStream("//Users//jessief//upload//community_rules");
			FileWriter fw = new FileWriter("//Users//jessief//upload//selected_rules");
			FileWriter fw1 = new FileWriter("//Users//jessief//upload//abandoned_rules");
			int count = 0;
			String str = null;
			InputStreamReader isr = new InputStreamReader(fis);
			BufferedReader br = new BufferedReader(isr);
			while ((str = br.readLine()) != null){
				if(Rule_Spout.shouldFilter(str)){
					fw1.write(str+"\n");
					continue;
				}
				count++;
				System.out.println("count:"+count);
				String aaa="\\(";
				String rule_header=null;
				String option=null;
				Pattern pattern_web = Pattern.compile(aaa);	
				Matcher matcher_web = pattern_web.matcher(str);
				if (matcher_web.find()) {
					System.out.println("matcher_web.find()");
					rule_header = str.substring(0, matcher_web.start());
					///***///
					System.out.println("rule_header:"+rule_header);
					option = str.substring(matcher_web.start()+1,str.length()-1);
					///***///
					System.out.println("rule_option:"+option);
					//RuleOption ro = new RuleOption();//新建一个规则选项类
					//String option = (String)rule_option.get(i);
					
//					int pos = option.indexOf("content");
//					String noncontent = option;
//					String content = "none";
//					if(pos != -1) {//存在content选项
//						noncontent = option.substring(0, pos);
//						content = option.substring(pos, option.length());
//					}
//					
//					//解析noncontent
//					String[] field = noncontent.split(";");
//					//存储最后的警告信息
//					String msg = field[0].split(":")[1];
//					ro.headMap.put("msg", msg);
					String[] field = option.split(";");
					int field_travel = 0;
					for(; field_travel <field.length; field_travel++){
						// key[j] = field[j].split(":")[0];
						// value[j]=field[j].split(":")[1];
						 if(field[field_travel].equals(""))
							 break;
						 String k = field[field_travel].split(":")[0];
						 
					 }
					//表示未被过滤
						fw.write(str+"\n");	
						
					
					
					
					//ro.headMap存储了content字段之前的内容
//					 if(content.equals("none")) {
//						 res.add(ro);
//						 continue;
//					 }
					 
					 //进行content以及以后的内容构建
//					 String[] con = content.split("content");
//					 int con_len = con.length;
//					 for(int j = 1; j < con_len; j++) {
//						 //Map<String, String> aContent = new LinkedHashMap<String, String>(50);
//						 String[] block = con[j].split(";");
//						 
//						 int block_len = block.length;
//						 for (int k = 0; k < block_len - 1; k++) {
//							 String first = block[k].split(":")[0];
//							 //System.out.println("the first is"+first);
//							 if(shouldFilter(first)){
//								 continue;
//							 }
//						 }//对一个content内的选项进行创建
//						//打印顺利通过的rule的内容
//						 fw.write(count+":"+str+"\n");						 
//					 }//创建一个option内的所有content					
				}
			}			
		}catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	
	public static boolean shouldFilter2(String key) {
		if(key.equals(" flowbits")||key.equals(" itype")||key.equals(" icode")||key.equals(" icmp_id")||key.equals(" icmp_seq")||key.equals(" stream_reassemble")||key.equals(" stream_size")
				||key.equals(" protected_content")||key.equals(" hash")||key.equals(" length")||key.equals(" rawbytes")||key.equals(" base64_decode")||key.equals(" base64_data")||key.equals(" byte_test")||key.equals(" byte_jump")||key.equals(" byte_extract")||key.equals(" byte_math")||key.contains(" http")||key.equals(" fast_pattrn")||key.equals(" uricontent")||key.equals(" urilen")||key.equals(" file_data")||key.equals(" pcre")||key.equals(" ftpbounce")||key.equals(" asn1")||key.equals(" cvs")||key.contains(" dce")||key.contains(" sip")||key.contains(" gtp")||key.contains(" ssl"))
			return true;
		return false;
	}

	
}
