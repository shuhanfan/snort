import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import snort.test.Helpers.DealOption;

public class KMPTest {
	public  static void main(String arg[]) {
		String ori = "64";
		String pat = "\"AB|43|D\"";
		boolean ignoreCase = false;
		boolean negative = false;
		byte[] b = new byte[]{65,66,67,68,69,65,66,72,73,74,65,66,43,65,66,67,68};
 		Map<Integer, ArrayList<Integer>> res = new HashMap<Integer, ArrayList<Integer>>();
 		int pattern_len = 0;
		int ret = DealOption.KMP(pat, b, 1, res, ignoreCase);
		System.out.println(ret);
		
	}
	
	

}
