
package rsa.utils;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;

import javax.crypto.Cipher;
/**
 *@项目名称：EncryptUtils  
 *@包名： rsa.utils
 *@类名：RSAUtils.java
 *@类描述：TODO
 *@创建人：tom
 *@创建日期：2015年12月21日
 *@修改人：
 *@修改时间：
 *@修改备注：
 *@versions  
 *@说明：
 * RSA 工具类。提供加密，解密，生成密钥对等方法。
 * 需要到http://www.bouncycastle.org下载bcprov-jdk14-123.jar。
 * RSA加密原理概述  
 * RSA的安全性依赖于大数的分解，公钥和私钥都是两个大素数（大于100的十进制位）的函数。  
 * 据猜测，从一个密钥和密文推断出明文的难度等同于分解两个大素数的积  
 * ===================================================================  
 * （该算法的安全性未得到理论的证明）  
 * ===================================================================  
 * 密钥的产生：  
 * 1.选择两个大素数 p,q,计算 n=p*q;  
 * 2.随机选择加密密钥 e,要求 e 和 (p-1)*(q-1)互质  
 * 3.利用 Euclid 算法计算解密密钥 d , 使其满足 e*d = 1(mod(p-1)*(q-1)) (其中 n,d 也要互质)  
 * 4:至此得出公钥为 (n,e) 私钥为 (n,d)  
 * ===================================================================  
 * 加解密方法：  
 * 1.首先将要加密的信息 m(二进制表示) 分成等长的数据块 m1,m2,...,mi 块长 s(尽可能大) ,其中 2^s<n  
 * 2:对应的密文是： ci = mi^e(mod n)  
 * 3:解密时作如下计算： mi = ci^d(mod n)  
 * ===================================================================  
 * RSA速度  
 * 由于进行的都是大数计算，使得RSA最快的情况也比DES慢上100倍，无论 是软件还是硬件实现。  
 * 速度一直是RSA的缺陷。一般来说只用于少量数据 加密。 
 * RSA是非对称算法，加密密钥和解密密钥是不一样的，或者说不能由其中一个密钥推导出另一个密钥。
 * 密钥尺寸大，加解密速度慢，一般用来加密少量数据 。
 */

public class RSAUtils {

	//密钥对
	private KeyPair keyPair = null;
	/**
	 * 初始化密钥对
	 */
	public RSAUtils(){
		try {
			this.keyPair = this.generateKeyPair();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * 生成密钥对
	 * @return KeyPair
	 * @throws Exception
	 */
	private KeyPair generateKeyPair() throws Exception {
		try {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA",new org.bouncycastle.jce.provider.BouncyCastleProvider());
			//这个值关系到块加密的大小，可以更改，但是不要太大，否则效率会低
			final int KEY_SIZE = 1024;
			keyPairGen.initialize(KEY_SIZE, new SecureRandom());
			KeyPair keyPair = keyPairGen.genKeyPair();
			return keyPair;
		} catch (Exception e) {

			throw new Exception(e.getMessage());
		}
	}



	/**
	 * 生成公钥
	 * @param modulus
	 * @param publicExponent
	 * @return RSAPublicKey
	 * @throws Exception
	 */
	private RSAPublicKey generateRSAPublicKey(byte[] modulus, byte[] publicExponent) throws Exception {

		KeyFactory keyFac = null;
		try {
			keyFac = KeyFactory.getInstance("RSA", new org.bouncycastle.jce.provider.BouncyCastleProvider());
		} catch (NoSuchAlgorithmException ex) {
			throw new Exception(ex.getMessage());
		}
		RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(publicExponent));
		try {
			return (RSAPublicKey) keyFac.generatePublic(pubKeySpec);
		} catch (InvalidKeySpecException ex) {
			throw new Exception(ex.getMessage());
		}

	}

	/**
	 * 生成私钥
	 * @param  modulus
	 * @param  privateExponent
	 * @return RSAPrivateKey
	 * @throws Exception
	 */
	private RSAPrivateKey generateRSAPrivateKey(byte[] modulus, byte[] privateExponent) throws Exception {
		KeyFactory keyFac = null;
		try {
			keyFac = KeyFactory.getInstance("RSA", new org.bouncycastle.jce.provider.BouncyCastleProvider());
		} catch (NoSuchAlgorithmException ex) {
			throw new Exception(ex.getMessage());
		}
		RSAPrivateKeySpec priKeySpec = new RSAPrivateKeySpec(new BigInteger(modulus), new BigInteger(privateExponent));
		try {
			return (RSAPrivateKey) keyFac.generatePrivate(priKeySpec);
		} catch (InvalidKeySpecException ex) {
			throw new Exception(ex.getMessage());
		}
	}

	/**
	 * 返回公钥
	 * @return
	 * @throws Exception 
	 */
	public RSAPublicKey getRSAPublicKey() throws Exception{

		//获取公钥
		RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
		//获取公钥系数(字节数组形式)
		byte[] pubModBytes = pubKey.getModulus().toByteArray();
		//返回公钥公用指数(字节数组形式)
		byte[] pubPubExpBytes = pubKey.getPublicExponent().toByteArray();
		//生成公钥
		RSAPublicKey recoveryPubKey = this.generateRSAPublicKey(pubModBytes,pubPubExpBytes);
		return recoveryPubKey;
	}

	/**
	 * 获取私钥
	 * @return
	 * @throws Exception 
	 */
	public RSAPrivateKey getRSAPrivateKey() throws Exception{

		//获取私钥
		RSAPrivateKey priKey = (RSAPrivateKey) keyPair.getPrivate();
		//返回私钥系数(字节数组形式)
		byte[] priModBytes = priKey.getModulus().toByteArray();
		//返回私钥专用指数(字节数组形式)
		byte[] priPriExpBytes = priKey.getPrivateExponent().toByteArray();
		//生成私钥
		RSAPrivateKey recoveryPriKey = this.generateRSAPrivateKey(priModBytes,priPriExpBytes);
		return recoveryPriKey;
	}

	/** 
	 * 公钥加密 
	 *  
	 * @param data 
	 * @param publicKey 
	 * @return 
	 * @throws Exception 
	 */  
	public static String encryptByPublicKey(String data, RSAPublicKey publicKey)  
			throws Exception {  
		Cipher cipher = Cipher.getInstance("RSA");  
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);  
		// 模长  
		int key_len = publicKey.getModulus().bitLength() / 8;  
		// 加密数据长度 <= 模长-11  
		String[] datas = splitString(data, key_len - 11);  
		String mi = "";  
		//如果明文长度大于模长-11则要分组加密  
		for (String s : datas) {  
			mi += bcd2Str(cipher.doFinal(s.getBytes()));  
		}  
		return mi;  
	}  

	/** 
	 * 私钥解密 
	 *  
	 * @param data 
	 * @param privateKey 
	 * @return 
	 * @throws Exception 
	 */  
	public static String decryptByPrivateKey(String data, RSAPrivateKey privateKey)  
			throws Exception {  
		Cipher cipher = Cipher.getInstance("RSA");  
		cipher.init(Cipher.DECRYPT_MODE, privateKey);  
		//模长  
		int key_len = privateKey.getModulus().bitLength() / 8;  
		byte[] bytes = data.getBytes();  
		byte[] bcd = ASCII_To_BCD(bytes, bytes.length);  
		System.err.println(bcd.length);  
		//如果密文长度大于模长则要分组解密  
		String ming = "";  
		byte[][] arrays = splitArray(bcd, key_len);  
		for(byte[] arr : arrays){  
			ming += new String(cipher.doFinal(arr));  
		}  
		return ming;  
	}  
	/** 
	 * ASCII码转BCD码 
	 *  
	 */  
	public static byte[] ASCII_To_BCD(byte[] ascii, int asc_len) {  
		byte[] bcd = new byte[asc_len / 2];  
		int j = 0;  
		for (int i = 0; i < (asc_len + 1) / 2; i++) {  
			bcd[i] = asc_to_bcd(ascii[j++]);  
			bcd[i] = (byte) (((j >= asc_len) ? 0x00 : asc_to_bcd(ascii[j++])) + (bcd[i] << 4));  
		}  
		return bcd;  
	}  
	public static byte asc_to_bcd(byte asc) {  
		byte bcd;  

		if ((asc >= '0') && (asc <= '9'))  
			bcd = (byte) (asc - '0');  
		else if ((asc >= 'A') && (asc <= 'F'))  
			bcd = (byte) (asc - 'A' + 10);  
		else if ((asc >= 'a') && (asc <= 'f'))  
			bcd = (byte) (asc - 'a' + 10);  
		else  
			bcd = (byte) (asc - 48);  
		return bcd;  
	}  
	/** 
	 * BCD转字符串 
	 */  
	public static String bcd2Str(byte[] bytes) {  
		char temp[] = new char[bytes.length * 2], val;  

		for (int i = 0; i < bytes.length; i++) {  
			val = (char) (((bytes[i] & 0xf0) >> 4) & 0x0f);  
			temp[i * 2] = (char) (val > 9 ? val + 'A' - 10 : val + '0');  

			val = (char) (bytes[i] & 0x0f);  
			temp[i * 2 + 1] = (char) (val > 9 ? val + 'A' - 10 : val + '0');  
		}  
		return new String(temp);  
	}  
	/** 
	 * 拆分字符串 
	 */  
	public static String[] splitString(String string, int len) {  
		int x = string.length() / len;  
		int y = string.length() % len;  
		int z = 0;  
		if (y != 0) {  
			z = 1;  
		}  
		String[] strings = new String[x + z];  
		String str = "";  
		for (int i=0; i<x+z; i++) {  
			if (i==x+z-1 && y!=0) {  
				str = string.substring(i*len, i*len+y);  
			}else{  
				str = string.substring(i*len, i*len+len);  
			}  
			strings[i] = str;  
		}  
		return strings;  
	}  
	/** 
	 *拆分数组  
	 */  
	public static byte[][] splitArray(byte[] data,int len){  
		int x = data.length / len;  
		int y = data.length % len;  
		int z = 0;  
		if(y!=0){  
			z = 1;  
		}  
		byte[][] arrays = new byte[x+z][];  
		byte[] arr;  
		for(int i=0; i<x+z; i++){  
			arr = new byte[len];  
			if(i==x+z-1 && y!=0){  
				System.arraycopy(data, i*len, arr, 0, y);  
			}else{  
				System.arraycopy(data, i*len, arr, 0, len);  
			}  
			arrays[i] = arr;  
		}  
		return arrays;  
	}  
}
