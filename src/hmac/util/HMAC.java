package hmac.util;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import base64.util.BASE64Decoder;
import base64.util.BASE64Encoder;

/**
 * 
 * @author tom
 * 
 *HMAC，全称为“Hash Message Authentication Code”，中文名“散列消息鉴别码”，
 *主要是利用哈希算法，以一个密钥和一个消息为输入，生成一个消息摘要作为输出。
 *一般的，消息鉴别码用于验证传输于两个共 同享有一个密钥的单位之间的消息。
 *HMAC 可以与任何迭代散列函数捆绑使用。MD5 和 SHA-1 就是这种散列函数。
 *HMAC 还可以使用一个用于计算和确认消息鉴别值的密钥。
 *
 *这种结构的主要作用是：
 *1>不用修改就可以使用适合的散列函数，而且散列函数在软件方面表现的很好， 并且源码是公开和通用的。
 *2>可以保持散列函数原有的性能而不致使其退化。
 *3>可以使得基于合理的关于底层散列函数假设的消息鉴别机制的加密强度分析 便于理解。
 *4>当发现或需要运算速度更快或更安全的散列函数时，可以很容易的实现底层 散列函数的替换。
 *
 */
public class HMAC {
	/** 
	 * 定义加密方式 
	 * MAC算法可选以下多种算法 
	 * <pre> 
	 * HmacMD5 
	 * HmacSHA1 
	 * HmacSHA256 
	 * HmacSHA384 
	 * HmacSHA512 
	 * </pre> 
	 */  
	private final static String KEY_MAC = "HmacMD5";  

	/** 
	 * 全局数组 
	 */  
	private final static String[] hexDigits = { "0", "1", "2", "3", "4", "5",  
		"6", "7", "8", "9", "a", "b", "c", "d", "e", "f" };  

	/** 
	 * 构造函数 
	 */  
	public HMAC() {  

	}  

	/** 
	 * BASE64 加密 
	 * @param key 需要加密的字节数组 
	 * @return 字符串 
	 * @throws Exception 
	 */  
	public static String encryptBase64(byte[] key) throws Exception {  
		return (new BASE64Encoder()).encodeBuffer(key);  
	}  

	/** 
	 * BASE64 解密 
	 * @param key 需要解密的字符串 
	 * @return 字节数组 
	 * @throws Exception 
	 */  
	public static byte[] decryptBase64(String key) throws Exception {  
		return (new BASE64Decoder()).decodeBuffer(key);  
	}  

	/** 
	 * 初始化HMAC密钥 
	 * @return 
	 */  
	public static String init() {  
		SecretKey key;  
		String str = "";  
		try {  
			KeyGenerator generator = KeyGenerator.getInstance(KEY_MAC);  
			key = generator.generateKey();  
			str = encryptBase64(key.getEncoded());  
		} catch (NoSuchAlgorithmException e) {  
			e.printStackTrace();  
		} catch (Exception e) {  
			e.printStackTrace();  
		}  
		return str;  
	}  

	/** 
	 * HMAC加密 
	 * @param data 需要加密的字节数组 
	 * @param key 密钥 
	 * @return 字节数组 
	 */  
	public static byte[] encryptHMAC(byte[] data, String key) {  
		SecretKey secretKey;  
		byte[] bytes = null;  
		try {  
			secretKey = new SecretKeySpec(decryptBase64(key), KEY_MAC);  
			Mac mac = Mac.getInstance(secretKey.getAlgorithm());  
			mac.init(secretKey);  
			bytes = mac.doFinal(data);  
		} catch (Exception e) {  
			e.printStackTrace();  
		}  
		return bytes;  
	}  

	/** 
	 * HMAC加密 
	 * @param data 需要加密的字符串 
	 * @param key 密钥 
	 * @return 字符串 
	 */  
	public static String encryptHMAC(String data, String key) {  
		if (data.isEmpty()) {
			return null;  
		}
		byte[] bytes = encryptHMAC(data.getBytes(), key);  
		return byteArrayToHexString(bytes);  
	}  


	/** 
	 * 将一个字节转化成十六进制形式的字符串 
	 * @param b 字节数组 
	 * @return 字符串 
	 */  
	private static String byteToHexString(byte b) {  
		int ret = b;  
		//System.out.println("ret = " + ret);  
		if (ret < 0) {  
			ret += 256;  
		}  
		int m = ret / 16;  
		int n = ret % 16;  
		return hexDigits[m] + hexDigits[n];  
	}  

	/** 
	 * 转换字节数组为十六进制字符串 
	 * @param bytes 字节数组 
	 * @return 十六进制字符串 
	 */  
	private static String byteArrayToHexString(byte[] bytes) {  
		StringBuffer sb = new StringBuffer();  
		for (int i = 0; i < bytes.length; i++) {  
			sb.append(byteToHexString(bytes[i]));  
		}  
		return sb.toString();  
	}  

	/** 
	 * 测试方法 
	 * @param args 
	 */  
	public static void main(String[] args) throws Exception {  
		String key = HMAC.init();  
		System.out.println("Mac密钥:\n" + key);  
		String word = "123";  
		System.out.println(encryptHMAC(word, key));  
	}  
}
