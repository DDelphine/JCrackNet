package com.xieqixin.net;

public class Tools {
	private static int NumMapping(String s){
		int r = 0;
		switch (s) {
		case "A":
			r = 10;
			break;
		case "B":
			r = 11;
			break;
		case "C":
			r = 12;
			break;
		case "D":
			r = 13;
			break;
		case "E":
			r = 14;
			break;
		case "F":
			r = 15;
			break;
		default:
			r = Integer.parseInt(s);
			break;
		}
		return r;
	}
	
	public static int HexConvertToDec(String s){
		int l = s.length();
		int r = 0;
		int w = 1;
		
		for(int i=l-1; i>=0; i--){
			r += NumMapping(s.substring(i, i+1)) * w;
			w *= 16;
		}
		return r;
	}
	
	public static int[] HexConvertToBin(String s){
		int l = s.length();
		int[] binaryList = new int[16];
	    for(int i=0; i<l; i++){ 
	    	int dec = HexConvertToDec(s.charAt(i)+"");
	    	for(int count=3; count>=0; count--){
	    		binaryList[i*4+count] = dec % 2;
	    		dec = dec / 2;
	    	}
	    }
	    return binaryList;
		//十六进制转换为2进制
	}
	
	static int times = 0;
	static int index = 0;
	public static int getAppearTimes(String str1, String str2){
		index = str1.indexOf(str2);
			
		if(index != -1 && index <= str1.length() - str2.length()){
			times ++;
			getAppearTimes(str1.substring(index + str2.length()),str2);
		}
		return times;
	}
	
	public static String HexConvertToDecString(String s){
		int l = s.length();
		int r = 0;
		int w = 1;
		
		for(int i=l-1; i>=0; i--){
			r += NumMapping(s.substring(i, i+1)) * w;
			w *= 16;
		}
		return String.valueOf(r);
	}
	
	public static String HexConvertToIP(String s){
		String[] str = {
					s.substring(0, 2),
					s.substring(3, 5),
					s.substring(6, 8),
					s.substring(9, 11)};
		String r = "";
		
		for(int i=0; i<4; i++){
			r += HexConvertToDec(str[i]) + ".";
		}
		return r.substring(0, r.length() - 1);
	}
	
	public static String BinaryConvertToDec(String s){
		int l = s.length();
		int r = 0;
		int w = 1;
		
		for(int i=l-1; i>=0; i--){
			r += NumMapping(s.substring(i, i+1)) * w;
			w *= 2;
		}
		return String.valueOf(r);
	}
	
	public static String FixLengthWithZeros(String s, int l){
		int ori = s.length();
		for(int i=0; i<l - ori; i++){
			s = "0" + s;
		}
		return s;
	}
	
	public static String ASCIIToString(String s){
		String r = "";
		for(int i=0; i<s.length(); i+=2){
			int tmp = Tools.HexConvertToDec(s.substring(i, i+2));
			r += (char)tmp;
		}
		return r;
	}
}
