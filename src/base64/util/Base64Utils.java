package base64.util;

import java.io.UnsupportedEncodingException;
/**
 *@项目名称：EncryptUtils  
 *@包名： base64.util
 *@类名：Base64Utils.java
 *@类描述：TODO
 *@创建人：tom
 *@创建日期：2015年12月21日
 *@修改人：
 *@修改时间：
 *@修改备注：
 *@versions  
 *
 *		类功能说明： 
 */
public class Base64Utils {
	/**
	 * base64编码
	 * @param str
	 * @return
	 */
	public static String getBase64(String str) {  
		byte[] b = null;  
		String s = null;  
		try {  
			b = str.getBytes("utf-8");  
		} catch (UnsupportedEncodingException e) {  
			e.printStackTrace();  
		}  
		if (b != null) {  
			s = new BASE64Encoder().encode(b);  
		}  
		return s;  
	}  

	/**
	 * 获取base64编码的数据
	 * @param s
	 * @return
	 */
	public static String getFromBase64(String s) {  
		byte[] b = null;  
		String result = null;  
		if (s != null) {  
			BASE64Decoder decoder = new BASE64Decoder();  
			try {  
				b = decoder.decodeBuffer(s);  
				result = new String(b, "utf-8");  
			} catch (Exception e) {  
				e.printStackTrace();  
			}  
		}  
		return result;  
	}  
}
