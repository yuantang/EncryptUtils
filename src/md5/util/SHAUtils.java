
package md5.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import base64.util.Base64Utils;
/**
 *@项目名称：EncryptUtils  
 *@包名： md5.util
 *@类名：SHAUtils.java
 *@类描述：TODO
 *@创建人：tom
 *@创建日期：2015年12月21日
 *@修改人：
 *@修改时间：
 *@修改备注：
 *@versions  
 *
 * 类功能说明： 
 *SHA1 和 MD5 是散列算法，将任意大小的数据映射到一个较小的、固定长度的唯一值。
 *加密性强的散列一定是不可逆的，这就意味着通过散列结果，无法推出任何部分的原始信息。
 *任何输入信息的变化，哪怕仅一位，都将导致散列结果的明显变化，这称之为雪崩效应。
 *散列还应该是防冲突的，即找不出具有相同散列结果的两条信息。
 *具有这些特性的散列结果就可以用于验证信息是否被修改。MD5 比 SHA1 大约快 33%
 */

public class SHAUtils {


	public final static String getSHA(String pwd) throws NoSuchAlgorithmException
	{
		MessageDigest md = MessageDigest.getInstance("SHA");//SHA 或者 MD5
		return Base64Utils.getBase64(md.digest(pwd.getBytes()).toString());
	}

	public final static String getMD5String(String s) {
		char hexDigits[] = { '0', '1', '2', '3', '4',
				'5', '6', '7', '8', '9',
				'A', 'B', 'C', 'D', 'E', 'F' };
		try {
			byte[] btInput = s.getBytes();
			//获得MD5摘要算法的 MessageDigest 对象
			MessageDigest mdInst = MessageDigest.getInstance("SHA");
			//使用指定的字节更新摘要
			mdInst.update(btInput);
			//获得密文
			byte[] md = mdInst.digest();
			//把密文转换成十六进制的字符串形式
			int j = md.length;
			char str[] = new char[j * 2];
			int k = 0;
			for (int i = 0; i < j; i++) {
				byte byte0 = md[i];
				str[k++] = hexDigits[byte0 >>> 4 & 0xf];
				str[k++] = hexDigits[byte0 & 0xf];
			}
			return new String(str);
		}
		catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
}
