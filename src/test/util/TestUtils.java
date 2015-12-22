/**
 *@项目名称：EncryptUtils  
 *@包名： test.util
 *@类名：TestUtils.java
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
package test.util;

import java.io.IOException;

import org.bouncycastle.jce.provider.JDKKeyFactory.RSA;

import rsa.utils.RSAUtils;
import md5.util.MD5Utils;
import des.util.DESUtils;
import base64.util.Base64Utils;
import aes.util.AESUtils;

/**
 * @author tom
 *
 */
public class TestUtils {
	static String content="1234567890";
	static   String key = "0987654321";

	public static void main(String[] args) throws IOException, Exception {
		//-----------------AES测试------------------------------------
		System.out.println("---------------AES测试-----------------------");
		String aesEncrypt=AESUtils.encrypt(content, key);
		String aesDncrypt=AESUtils.decrypt(aesEncrypt, key);
		System.out.println("加密前：content--------->"+content);
		System.out.println("加密后：aesEncrypt--------->"+aesEncrypt);
		System.out.println("解密后：aesDncrypt--------->"+aesDncrypt);
		//-----------------BASE64测试------------------------------------
		System.out.println("---------------BASE64测试-----------------------");		
		String getBase64=Base64Utils.getBase64(content);
		String fromBase64=Base64Utils.getFromBase64(getBase64);
		System.out.println("加密前：content--------->"+content);
		System.out.println("加密后：getBase64--------->"+getBase64);
		System.out.println("解密后：fromBase64--------->"+fromBase64);
		//-----------------DES测试------------------------------------
		System.out.println("---------------DES测试-----------------------");
		String desEncrypt=DESUtils.encrypt(content, key);
		String desDncrypt=DESUtils.decrypt(desEncrypt, key);
		System.out.println("加密前：content--------->"+content);
		System.out.println("加密后：desEncrypt--------->"+desEncrypt);
		System.out.println("解密后：desDncrypt--------->"+desDncrypt);
		//-----------------MD5测试------------------------------------
		System.out.println("---------------MD5测试-----------------------");
		String md51=MD5Utils.getMD5(content);
		String md52=MD5Utils.getMD5String(content);
		System.out.println("加密前：content--------->"+content);
		System.out.println("md51：md52--------->"+md52);
		System.out.println("md52：md52--------->"+md52);
		//-----------------RSA测试------------------------------------
		System.out.println("---------------RSA测试-----------------------");
		RSAUtils rsaUtils=new RSAUtils();
		System.out.println("公钥："+rsaUtils.getRSAPublicKey().getFormat());
		System.out.println("私钥："+rsaUtils.getRSAPrivateKey().getFormat());
		String rsaEncrypt=rsaUtils.encryptByPublicKey(content, rsaUtils.getRSAPublicKey());
		String rsaDncrypt=rsaUtils.decryptByPrivateKey(rsaEncrypt, rsaUtils.getRSAPrivateKey());
		System.out.println("加密前：content--------->"+content);
		System.out.println("rsaEncrypt：rsaEncrypt--------->"+rsaEncrypt);
		System.out.println("rsaDncrypt：rsaDncrypt--------->"+rsaDncrypt);


	}
}
