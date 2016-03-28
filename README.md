# EncryptUtils
总结了一下常用的一些加密方式：
			1)对称加密：AES DES RC4
			2)非对称加密：RSA
			3)编码：base64 
			4)摘要：MD5 SHA HMAC
 
测试类：                              
```Java
public static void main(String[] args) throws IOException, Exception {
		String content="1234567890";
		String key = "0987654321";
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
```
 
 测试结果：
 ```
 ---------------AES测试-----------------------
加密前：content--------->1234567890
加密后：aesEncrypt--------->82BBCA1E8FF05DAE79ADCE1840B84233
解密后：aesDncrypt--------->1234567890
---------------BASE64测试-----------------------
加密前：content--------->1234567890
加密后：getBase64--------->MTIzNDU2Nzg5MA==
解密后：fromBase64--------->1234567890
---------------DES测试-----------------------
加密前：content--------->1234567890
加密后：desEncrypt--------->TC1/2jxVU3vJAqGfwoZIQg==
解密后：desDncrypt--------->1234567890
---------------MD5测试-----------------------
加密前：content--------->1234567890
md51：md52--------->E807F1FCF82D132F9BB018CA6738A19F
md52：md52--------->E807F1FCF82D132F9BB018CA6738A19F
---------------RSA测试-----------------------
公钥：X.509
私钥：PKCS#8
128
加密前：content--------->1234567890
rsaEncrypt：rsaEncrypt--------->19D2FB2372CBDB252C914BB6A00C570C2A39E9837F6952DD5016C26C319041495662C5D33E720B4B1C6F4D115607A4C14AAA892D7E18749106F5615E538EC9F68EE7803D12E1C33A23E0A4579E0D8C3C1EA5CBBF500EFDA41F5EFFB78ED8B3306782379AA70A24937165B9C9A6E1DD61BE27BAA1F82D7CDAA27176CA3DDB4B2B
rsaDncrypt：rsaDncrypt--------->1234567890
```
 
 后期还会不断总结一些其他的加密方式和各自的优缺点以及使用场景。
 
