package com.xieqixin.net;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.swing.plaf.basic.BasicGraphicsUtils;
import javax.tools.Tool;

public class PackageReader {
	int standardFormatLen = 40;
	int len = 0;
	
	Map<String, String> m = new LinkedHashMap<String, String>();
	
	ARP arp;
	IP ip;
	
	StringBuilder hex = new StringBuilder();
	public PackageReader(String path) {
		try{
			int value;
			InputStream is = new FileInputStream(path);
			//持续从is中读取字节(InputStream.read()读取的是下一个字节)
			while(((value = is.read()) != -1)){
				if(++len > standardFormatLen){
					//System.out.println(len+"  "+value);
					hex.append(String.format("%02X ", value));// %02X意为:2位十六进制数
				}
			}
			is.close();
		}catch(IOException e){
			e.printStackTrace();
		}finally{
			
		}
		
		m.put("Destination", hex.substring(0, 17).replace(" ", ":"));
		m.put("Source", hex.substring(18, 35).replace(" ", ":"));
		
		String type = hex.substring(36, 41);
		switch(type){
			case "08 06":
				type = "ARP (0x0806)";
				m.put("Type", type);
				arp = new ARP(hex.substring(42));
				break; 
				
			case "08 00":
				type = "IPv4 (0x0800)";
				m.put("Type", type);
				ip = new IP(hex.substring(42));
				break;
				
			default:
				break;
		}
	}
}

class ARP{
	Map<String, String> m = new LinkedHashMap<String, String>();
	public ARP(String sb){
		String hardwareType = sb.substring(0, 5);
		switch(hardwareType){
		case "00 01": 
			hardwareType = "Ethernet (1)";
			m.put("Hardware Type", hardwareType);
			break;
			
		default:
			break;
		}
		
		String protocolType = sb.substring(6, 11);
		switch(protocolType){
		case "08 00": 
			protocolType = "IPv4 (0x0800)"; 
			m.put("Protocol Type", protocolType);
			break;
		
		default:
			break;
		}
		
		m.put("Hardware Size", Tools.HexConvertToDecString(sb.substring(12, 14)));

		m.put("Protocol Size", Tools.HexConvertToDecString(sb.substring(15, 17)));
		
		String opCode = sb.substring(18, 23);
		switch (opCode) {
		case "00 01":
			opCode = "request (1)";
			m.put("OpCode", opCode);
			break;
		case "00 02":
			opCode = "reply (2)";
			m.put("OpCode",opCode);
			break;
			
		default:
			break;
		}

		m.put("Sender MAC Address", sb.substring(24, 41).replace(" ", ":"));
		m.put("Sender IP Address", sb.substring(42, 53).replace(" ", ":"));
		m.put("Target MAC Address", sb.substring(54, 71).replace(" ", ":"));
		m.put("Target IP Address", sb.substring(72, 83).replace(" ", ":"));

	}
	
}

class IP{
	Map<String, String> m = new LinkedHashMap<String,String>();
	
	TCP tcp;
	UDP udp;
	ICMP icmp;
	IGMP igmp;
	IGMPOptions igmpOptions;
	
	public IP(String sb){	
		m.put("Version", sb.substring(0, 1));
		
		String headerLength = sb.substring(1, 2);
		m.put("Header Length", String.valueOf(Tools.HexConvertToDec(headerLength)*4) + "bytes (" + headerLength + ")");
		
		m.put("Service Type", Tools.HexConvertToDecString(sb.substring(3, 5)));
		m.put("Total Length", Tools.HexConvertToDecString(sb.substring(6, 11).replace(" ", "")));
		
		String identification = sb.substring(12, 17).replace(" ", "");
		m.put("Identification", "0x" + identification + " (" + Tools.HexConvertToDecString(identification) + ")");
		
		String fragmentOffset = null;
		String flags = null;
		String tmp = sb.substring(18, 23);
		tmp = tmp.replace(" ", "");
		tmp = Integer.toBinaryString(Tools.HexConvertToDec(tmp));
		switch (tmp.length()) {
		case 16:
			flags = "0x04 (Reserved bit)";
			fragmentOffset = Tools.BinaryConvertToDec(tmp.substring(3));
			break;
		case 15:
			flags = "0x02 (Don't fragments)";
			fragmentOffset = Tools.BinaryConvertToDec(tmp.substring(2));
			break;
		case 14:
			flags = "0x01 (More fragments)";
			fragmentOffset = Tools.BinaryConvertToDec(tmp.substring(1));
			break;
		default:
			flags = "0";
			fragmentOffset = Tools.BinaryConvertToDec(tmp);
			break;
		}
		m.put("Flags", flags);
		m.put("Fragment Offset", fragmentOffset);
	
		m.put("Time to Live", Tools.HexConvertToDecString(sb.substring(24, 26)));
		
		String protocol = Tools.HexConvertToDecString(sb.substring(27, 29));
		switch (protocol) {
		case "6":
			protocol = "TCP (6)";
			m.put("Protocol", protocol);
			tcp = new TCP(sb.substring(60));
			break;
		case "17":
			protocol = "UDP (17)";
			m.put("Protocol", protocol);
			udp = new UDP(sb.substring(60));
			break;
		case "1":
			protocol = "ICMP (1)";
			m.put("Protocol", protocol);
			icmp = new ICMP(sb.substring(60));
			break;
		case "2":
			protocol = "IGMP (2)";
			m.put("Protocol", protocol);
			igmp = new IGMP(sb.substring(72));
			break;
		default:
			break;
		}

		m.put("Header CheckSum", "0x" + sb.substring(30, 35).replace(" ", ""));
		m.put("Source IP Address", Tools.HexConvertToIP(sb.substring(36, 47)));
		m.put("Destination IP Address", Tools.HexConvertToIP(sb.substring(48, 59)));
		
		if(protocol == "IGMP (2)"){
			igmpOptions = new IGMPOptions(sb.substring(60, 71));
		}
		
	}
}

class TCP{
	Map<String, String> m = new LinkedHashMap<String, String>();
	TCPFlags flags;
	
	public TCP(String sb){
		
		m.put("Source Port", Tools.HexConvertToDecString(sb.substring(0, 5).replaceAll(" ", "")));
		m.put("Destination Port", Tools.HexConvertToDecString(sb.substring(6, 11).replace(" ", "")));
		m.put("Sequence Number", "0x" + sb.substring(12, 23).replace(" ", ""));
		m.put("Acknowledge", "0x" + sb.substring(24, 35).replace(" ", ""));
		m.put("Header Length", 
				String.valueOf(Tools.HexConvertToDec(sb.substring(36, 37))*4) + " bytes");
		
		flags = new TCPFlags(sb.substring(37, 41));

		m.put("Window Size", Tools.HexConvertToDecString(sb.substring(42, 47).replace(" ", "")));
		m.put("CheckSum", Tools.HexConvertToDecString(sb.substring(48, 53).replace(" ", "")));
		m.put("Urgent Pointer", Tools.HexConvertToDecString(sb.substring(54, 59).replace(" ", "")));
	}
}

class UDP{
	Map<String, String> m = new LinkedHashMap<String, String>();
	BOOTP bootp;
	DNS dns;
	SNMP snmp;
	
	public UDP(String sb){
		m.put("Source Port", 
				Tools.HexConvertToDecString(sb.substring(0, 5).replace(" ", "")));
		m.put("Destination Port", 
				Tools.HexConvertToDecString(sb.substring(6, 11).replace(" ", "")));
		m.put("Length", 
				Tools.HexConvertToDecString(sb.substring(12, 17).replace(" ", "")));
		m.put("CheckSum", 
				"0x" + sb.substring(18, 23).replace(" ", ""));
	
		switch (m.get("Source Port")) {
		case "68":
		case "67":
			bootp = new BOOTP(sb.substring(24));
		default:
			break;
		}
		switch (m.get("Destination Port")){
		case "53":
			dns = new DNS(sb.substring(24));
		case "161":
		case "162":
			snmp = new SNMP(sb.substring(24));
		default:
			break;
		}
	}
	
}

class DNS{
	Map<String,String> m = new LinkedHashMap<String,String>();
	
	public DNS(String sb){
		m.put("Transaction ID","0x"+sb.substring(0,5).replace(" ",""));
		String flags = sb.substring(6,11).replace(" ","");
		int[] flag = Tools.HexConvertToBin(flags);
		if(flag[0] == 0)
			m.put("Response: Message is a query",flag[0]+"");
		else if(flag[0] == 1)
			m.put("Response: Message is a response",flag[0]+"");
		if(flag[3]==flag[4])
			m.put("Opcode: Standard query (0)","0000");
		else if(flag[3] ==0 && flag[4] == 1)
			m.put("Opcode: Inverse query(1)","0010");
		else if(flag[3] ==1 && flag[4] == 0)
			m.put("Opcode: Status (2)","0010");
		if(flag[6] == 0)
			m.put("Truncated: Message is not truncated", flag[6]+"");
		else
			m.put("Truncated: Message is truncated", flag[6]+"");
		if(flag[7] == 1)
			m.put("Recursive desired: Do query recursively", flag[7]+"");
		m.put("Z: reserved (0)","000");
		m.put("Non-authenticated data:  Unacceptable", "0");
		m.put("Questions ", Tools.HexConvertToDecString(sb.substring(12, 17).replace(" ", "")));
		m.put("Answer RRs", Tools.HexConvertToDecString(sb.substring(18, 23).replace(" ", "")));
		m.put("Authority RRs", Tools.HexConvertToDecString(sb.substring(24, 29).replace(" ", "")));
		m.put("Additional RRs", Tools.HexConvertToDecString(sb.substring(30, 35).replace(" ", "")));
	}
}

class SNMP{
	Map<String,String> m = new LinkedHashMap<String,String>();
	PDU pdu;
	public SNMP(String sb){
		m.put("version: version-",Tools.HexConvertToDecString(sb.substring(12,14)));
		String[] s = sb.substring(21,38).split(" ");
		StringBuilder community = new StringBuilder();
		for(String str : s){
			community.append((char)Integer.parseInt(str,16));
		}
		String com = community.toString();
		m.put("community",com);
		switch(sb.substring(40,41)){
		case "0":
			m.put("data", "get-request");
			pdu = new PDU(sb.substring(51));
			break;
		case "1":
			m.put("data", "get-next-request");
			pdu = new PDU(sb.substring(51));
			break;
		case "2":
			m.put("data", "set-request");
			pdu = new PDU(sb.substring(51));
			break;
		case "3":
			m.put("data", "get-response");
		    pdu = new PDU(sb.substring(51));
			break;
		case "4":
			m.put("data", "trap");
			break;
		default:
			break;
		}
	}
}

class PDU{
	Map<String,String> m = new LinkedHashMap<String,String>();
	VB vb;
	int count;
	public PDU(String sb){
		m.put("request-id",sb.substring(0,2));
		switch(sb.substring(9,11)){
		case "00":
			m.put("error-status","noError (0)");
			break;
		case "01":
			m.put("error-status","tooBig (1)");
		case "02":
			m.put("error-status","noSuchName (2)");
			break;
		case "03":
			m.put("error-status","badValue (3)");
			break;
		case "04":
			m.put("error-status","readOnly (4)");
			break;
		case "05":
			m.put("error-status","genErr (5)");
			break;
		default :
			break;
		}
		m.put("error-index",sb.substring(18,20));
		m.put("variable-bindings","item");
		vb = new VB(sb.substring(21));
	}
}

class VB{
	Map<String,String> m = new LinkedHashMap<String,String>();
	
	public VB(String sb){
		m.put("Object Name",sb.substring(18,23) +"."+
				Tools.HexConvertToDec(sb.substring(24,26)) +"."+
				Tools.HexConvertToDec(sb.substring(27,29)) +"."+ 
				Tools.HexConvertToDec(sb.substring(30,32)) +"."+
				Tools.HexConvertToDec(sb.substring(33,35)) +"."+
				Tools.HexConvertToDec(sb.substring(36,38)) +"."+
				Tools.HexConvertToDec(sb.substring(40,41)));
		m.put("Value","(NULL)");
	}
}

class ICMP{
	Map<String,String> m = new LinkedHashMap<String,String>();
	
	public ICMP(String sb){
		m.put("Type", 
				Tools.HexConvertToDecString(sb.substring(0, 2)));
		m.put("Code",
				Tools.HexConvertToDecString(sb.substring(3, 5)));
		m.put("CheckSum", 
				"0x" + sb.substring(6, 11).replace(" ", ""));
		m.put("Identifier", 
				"0x" + sb.substring(12, 17).replace(" ", ""));
		m.put("Sequence Number",
				"0x" + sb.substring(18, 23).replace(" ", ""));
	}
}


class IGMP{
	Map<String, String> m = new LinkedHashMap<String, String>();
	
	public IGMP(String sb){
		m.put("Type", 
				Tools.HexConvertToDecString(sb.substring(0, 2)));
		m.put("Max Resp Time",
				Tools.HexConvertToDecString(sb.substring(3, 5)) + " sec");
		m.put("CheckSum", 
				"0x" + sb.substring(6, 11).replace(" ", ""));
		m.put("Multicast Address", Tools.HexConvertToIP(sb.substring(12, 23)));
	}
}

class TCPFlags{
	Map<String, String> m = new LinkedHashMap<String, String>();
	
	public TCPFlags(String sb){
		m.put("Nonce", "0");
		m.put("Congestion Window Reduced (CWR)", "0");
		m.put("ECH-Echo", "0");
		m.put("Urgent", "0");
		m.put("Acknowledgment", "0");
		m.put("Push", "0");
		m.put("Reset", "0");
		m.put("Syn", "0");
		m.put("Fin", "0");
		
		sb = sb.replace(" ", "");
		sb = Tools.FixLengthWithZeros(Integer.toBinaryString(Tools.HexConvertToDec(sb)), 9);
		
		Iterator iter = m.entrySet().iterator();
		int i = 0;
		while(iter.hasNext()){
			Map.Entry<String, String> entry = (Map.Entry<String, String>)iter.next();
			entry.setValue(sb.substring(i, i+1));
			i++;
		}
	}
}

class IGMPOptions{
	Map<String, String> m = new LinkedHashMap<String, String>();
	
	public IGMPOptions(String sb){
		m.put("Type", Tools.HexConvertToDecString(sb.substring(0, 2)));
		m.put("Length", Tools.HexConvertToDecString(sb.substring(3, 5)));
		m.put("Router Alert", 
			"Router shall examine packet (" + Tools.HexConvertToDecString(sb.substring(6, 11).replace(" ", "")) + ")");
	}
}

class BOOTP{
	Map<String, String> m = new LinkedHashMap<String, String>();
	ArrayList<BOOTPOption> bootpOptions = new ArrayList<BOOTPOption>();
	
	public BOOTP(String sb){
		String messageType = Tools.HexConvertToDecString(sb.substring(0, 2));
		switch (messageType) {
		case "1":
			m.put("Message Type", "Boot Request (" + messageType + ")");
			break;

		default:
			break;
		}
		
		String hardwareType = sb.substring(3, 5);
		switch (hardwareType) {
		case "01":
			m.put("Hardware Type", "Ethernet (0x" + hardwareType + ")");
			break;

		default:
			break;
		}
		
		m.put("Hardware Address Length", Tools.HexConvertToDecString(sb.substring(6, 8)));
		m.put("Hops", Tools.HexConvertToDecString(sb.substring(9, 11)));
		m.put("Transaction ID", "0x" + sb.substring(12, 23).replace(" ", ""));
		m.put("Seconds Elapsed", Tools.HexConvertToDecString(sb.substring(24, 29).replace(" ", "")));
		m.put("Bootp Flags", "0x" + sb.substring(30, 35).replace(" ", ""));
		m.put("Client IP Address", Tools.HexConvertToIP(sb.substring(36, 47)));
		m.put("Your (client) IP Address", Tools.HexConvertToIP(sb.substring(48, 59)));
		m.put("Next Server IP Address", Tools.HexConvertToIP(sb.substring(60, 71)));
		m.put("Relay Agent IP Address", Tools.HexConvertToIP(sb.substring(72, 83)));
		m.put("Client MAC Address", sb.substring(84, 101).replace(" ", ":"));
		m.put("Client Hardware Address Padding", sb.substring(102, 131).replace(" ", ""));
		String serverHostName = sb.substring(132, 323);
		m.put("Server Host Name", "NOT GIVEN");
		String bootFileName = sb.substring(324, 707);
		m.put("Boot File Name", "NOT GIVEN");
		String magicCookie = sb.substring(708, 719);
		m.put("Magic Cookie", "DHCP");
		
		int pos = 720;
		int stop = 0;
		while((pos < sb.length()) && (stop == 0)){
			switch (Tools.HexConvertToDecString(sb.substring(pos, pos+2))) {
			case "51":
				BOOTPOption option51 = new BOOTPOption51(sb.substring(pos));
				bootpOptions.add(option51);
				pos += Integer.parseInt(option51.m.get("Length")) * 3 + 6;
				break;
			case "81":
				BOOTPOption option81 = new BOOTPOption81(sb.substring(pos));
				bootpOptions.add(option81);
				pos += Integer.parseInt(option81.m.get("Length")) * 3 + 6;
				break;
			case "54":
				BOOTPOption option54 = new BOOTPOption54(sb.substring(pos));
				bootpOptions.add(option54);
				pos += Integer.parseInt(option54.m.get("Length")) * 3 + 6;
				break;
			case "50":
				BOOTPOption option50 = new BOOTPOption50(sb.substring(pos));
				bootpOptions.add(option50);
				pos += Integer.parseInt(option50.m.get("Length")) * 3 + 6;
				break;
			case "57":
				BOOTPOption option57 = new BOOTPOption57(sb.substring(pos));
				bootpOptions.add(option57);
				pos += Integer.parseInt(option57.m.get("Length")) * 3 + 6;
				break;
			case "53":
				BOOTPOption option53 = new BOOTPOption53(sb.substring(pos));
				bootpOptions.add(option53);
				pos += Integer.parseInt(option53.m.get("Length")) * 3 + 6;
				break;
			case "61":
				BOOTPOption option61 = new BOOTPOption61(sb.substring(pos));
				bootpOptions.add(option61);
				pos += Integer.parseInt(option61.m.get("Length")) * 3 + 6;
				break;
			case "12":
				BOOTPOption option12 = new BOOTPOption12(sb.substring(pos));
				bootpOptions.add(option12);
				pos += Integer.parseInt(option12.m.get("Length")) * 3 + 6;
				break;
			case "60":
				BOOTPOption option60 = new BOOTPOption60(sb.substring(pos));
				bootpOptions.add(option60);
				pos += Integer.parseInt(option60.m.get("Length")) * 3 + 6;
				break;
			case "55":
				BOOTPOption option55 = new BOOTPOption55(sb.substring(pos));
				bootpOptions.add(option55);
				pos += Integer.parseInt(option55.m.get("Length")) * 3 + 6;
				break;
			case "255":
				BOOTPOption option255 = new BOOTPOption255(sb.substring(pos));
				bootpOptions.add(option255);
				pos += 3;
				stop = 1;
				break;
			default:
				break;
			}
		}
		m.put("Padding", sb.substring(pos).replace(" ", ""));
		
	}
}

class BOOTPOption51 extends BOOTPOption{
	public BOOTPOption51(String sb){
		m.put("Option", "(51) IP Address Lease Time");
		m.put("Length", Tools.HexConvertToDecString(sb.substring(3, 5)));
		m.put("IP Address Lease Time", Tools.HexConvertToDecString(sb.substring(6, 
			Integer.parseInt(m.get("Length"))*3 - 1 + 6).replace(" ", "")) + "s");
	} 
}

class BOOTPOption54 extends BOOTPOption{
	public BOOTPOption54(String sb){
		m.put("Option", "(54) DHCP Message Type");
		m.put("Length", Tools.HexConvertToDecString(sb.substring(3, 5)));
		m.put("DHCP", Tools.HexConvertToDecString(sb.substring(6, 8)));
	}
}

class BOOTPOption57 extends BOOTPOption{
	public BOOTPOption57(String sb){
		m.put("Option", "(57) Maximum DHCP Message Size");
		m.put("Length", Tools.HexConvertToDecString(sb.substring(3, 5)));
		m.put("Maximum DHCP Message Size", Tools.HexConvertToDecString(sb.substring(6, 11).replace(" ", "")));
	}
}

class BOOTPOption50 extends BOOTPOption{
	public BOOTPOption50(String sb){
		m.put("Option", "(50) Requested IP Address");
		m.put("Length", Tools.HexConvertToDecString(sb.substring(3, 5)));
		m.put("Request IP Address", Tools.HexConvertToIP(sb.substring(6, 17)));
	}
}

class BOOTPOption53 extends BOOTPOption{

	public BOOTPOption53(String sb){
		m.put("Option", "(53) DHCP Message Type");
		m.put("Length", Tools.HexConvertToDecString(sb.substring(3, 5)));
		m.put("DHCP", Tools.HexConvertToDecString(sb.substring(6, 8)));
	}
}

class BOOTPOption61 extends BOOTPOption{

	public BOOTPOption61(String sb){
		m.put("Option", "(61) Client Identifier");
		m.put("Length", Tools.HexConvertToDecString(sb.substring(3, 5)));
		String hardwareType = sb.substring(6, 8);
		switch (hardwareType) {
		case "01":
			m.put("Hardware Type", "Ethernet (0x01)");
			break;

		default:
			break;
		}
		m.put("Client MAC Address", sb.substring(9, 26).replace(" ", ":"));
	}
}

class BOOTPOption12 extends BOOTPOption{
	
	public BOOTPOption12(String sb){
		m.put("Option", "(12) Host Name");
		m.put("Length", Tools.HexConvertToDecString(sb.substring(3, 5)));
		m.put("Host Name", 
			Tools.ASCIIToString(sb.substring(6, 6+Integer.parseInt(m.get("Length"))*3).replace(" ", "")));
	}
}

class BOOTPOption60 extends BOOTPOption{

	public BOOTPOption60(String sb){
		m.put("Option", "(60) Vendor Class Identifier");
		m.put("Length", Tools.HexConvertToDecString(sb.substring(3, 5)));
		m.put("Vendor Class Identifier", 
			Tools.ASCIIToString(sb.substring(6, 6+Integer.parseInt(m.get("Length"))*3).replace(" ", "")));
	}
}

class BOOTPOption55 extends BOOTPOption{

	public BOOTPOption55(String sb){
		m.put("Option", "(55) Parameter Request List");
		m.put("Length", Tools.HexConvertToDecString(sb.substring(3, 5)));
		for(int i=0; i<Integer.parseInt(m.get("Length"))*3; i+=3){
			m.put("Parameter Request List Item " + String.valueOf(i/3 + 1), Tools.HexConvertToDecString(sb.substring(6 + i, 6 + i + 2)));
		}
	}
}

class BOOTPOption81 extends BOOTPOption{
	public BOOTPOption81(String sb){
		m.put("Option", "(81) Client Fully Qualified Domain Name");
		m.put("Length", Tools.HexConvertToDecString(sb.substring(3, 5)));
		m.put("Flags", "0x" + sb.substring(6, 8));
		m.put("A-RR Result", Tools.HexConvertToDecString(sb.substring(9, 11)));
		m.put("PTR-RR Result", Tools.HexConvertToDecString(sb.substring(12, 14)));
		m.put("Client Name", Tools.ASCIIToString(sb.substring(15, 
				(Integer.parseInt(m.get("Length")) - 3) * 3 - 1 + 15).replace(" ", "")));
	}
}

class BOOTPOption255 extends BOOTPOption{

	public BOOTPOption255(String sb){
		m.put("Option", "(255) End");
		m.put("Option End", "255");
	}
}