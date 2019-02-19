package com.xieqixin.net;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Iterator;
import java.util.Map;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTree;
import javax.swing.ScrollPaneConstants;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;

public class JNetWOrker {
	//声明窗口
	private JFrame frame;
	//JTextArea:窗口中放置文本的区域（可放置多行文本）
	private JTextArea binaryText;
	//自定义类
	private PackageReader pr = null;
	//树结构通用节点，声明根节点
	DefaultMutableTreeNode root = null;
	//构建以root为根节点的JTree
	JTree tree = new JTree(root);

	public static void main(String[] args) {
		JNetWOrker wOrker = new JNetWOrker();
		wOrker.go();
		
	}
	public void go(){
		//窗口名为JNetWOrker
		frame = new JFrame("JNetWOrker");
		//放置控件的容器，建立一个具有double buffering功能的JPanel,默认的布局管理是Flow Layout（组件从左至右水平放置在容器中）
		JPanel mainPanel = new JPanel();
		//盒子布局（可以指定在容器中是否对控件进行水平or垂直放置，Y_AXIS应该是垂直放置）
		mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        //创建JLabel：读取的数据
		JLabel binaryLabel = new JLabel("binaryText");
		//设置对齐方式：沿X轴对齐，元素放置在中间
		binaryLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
		// 创建JLabel:显示的结果
		JLabel resultLabel = new JLabel("result");
		resultLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
		//构造10行30列的的TextArea
		binaryText = new JTextArea(10, 30);
		//设置文本区自动换行策略
		binaryText.setLineWrap(true);
		//设置断行不断字策略
		binaryText.setWrapStyleWord(true);
		binaryText.setAlignmentX(Component.CENTER_ALIGNMENT);
		//创建滚动条面板 显示binaryText(十六进制数据报)
		JScrollPane binaryScroll = new JScrollPane(binaryText);
		//设置何时出现纵向滚动条
		binaryScroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
		//设置何时出现横向滚动条
		binaryScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		// 创建Convert按钮
		JButton convertButton = new JButton("Convert");
		//To tell when a JButton is pressed
		convertButton.addActionListener(new ConvertButtonListner());
		//按键水平对齐置中
		convertButton.setAlignmentX(Component.CENTER_ALIGNMENT);
		//树水平对齐置中
		tree.setAlignmentX(Component.CENTER_ALIGNMENT);
		//创建滚动条面板 显示Tree(协议分析结构图)
		JScrollPane treeScroll = new JScrollPane(tree);
		treeScroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
		treeScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		
		//Panel中的各个组件
		mainPanel.add(binaryLabel);
		mainPanel.add(binaryScroll);
		mainPanel.add(resultLabel);
		mainPanel.add(treeScroll);
		mainPanel.add(convertButton);
		
		//新建菜单栏(菜单栏MenuBar->菜单JMenu->菜单项JMenuItem)
		JMenuBar menuBar = new JMenuBar();
		//用给定标签(File and About)构建菜单
		JMenu fileMenu	= new JMenu("File");
		JMenu aboutMenu = new JMenu("About");
		//添加菜单项
		JMenuItem helpMenuItem = new JMenuItem("Help");
		helpMenuItem.addActionListener(new helpMenuListener());
		JMenuItem loadMenuItem = new JMenuItem("Load");
		loadMenuItem.addActionListener(new LoadMenuListener());
		
		fileMenu.add(loadMenuItem);
		aboutMenu.add(helpMenuItem);
		menuBar.add(fileMenu);
		menuBar.add(aboutMenu);
		
		//frame中的菜单项
		frame.setJMenuBar(menuBar);
		//得到frame的内容面板并在之中添加mainPanel容器
		frame.getContentPane().add(BorderLayout.CENTER, mainPanel);
		//设置frame为可以容纳所有组件的最小尺寸
		frame.pack();
		frame.setVisible(true);
	 }
	//helpMenuListener继承自ActionListener，触发actionPerformerd
	public class helpMenuListener implements ActionListener{
		public void actionPerformed(ActionEvent ev){
			//消息提示框
			JOptionPane.showMessageDialog(frame, 
					"Current Supported Protocols:\n"
					+ "ARP、TCP、UDP、ICMP、IGMP、DHCP"
					, "HELP", 1); 
		}
	}
	
	 public class LoadMenuListener implements ActionListener{
		 public void actionPerformed(ActionEvent ev){
			 //构建一个文件对话框，默认家目录为起始路径
			 JFileChooser fileOpen = new JFileChooser();
			 //打开文件对话框
			 fileOpen.showOpenDialog(frame);
			 try{
				 //getSelectedFile取得文件对象,getPath取得文件对象的路径
				 LoadFile(fileOpen.getSelectedFile().getPath());
			 }catch(NullPointerException e){
				 e.printStackTrace();
			 }
			 binaryText.setText(pr.hex.toString());
		 }
	 }
	 
	 public class ConvertButtonListner implements ActionListener{
		 public void actionPerformed(ActionEvent ev){
			 if(pr == null){
				JOptionPane.showMessageDialog(frame, "LOAD FILE PLZ!", "WARNING", 1); 
			 }
			 else{
				 DefaultMutableTreeNode root2 = new DefaultMutableTreeNode("Net Package Structure");
				 DefaultMutableTreeNode ethernet = new DefaultMutableTreeNode("EtherNet");

				 Iterator iter = pr.m.entrySet().iterator();
				 while(iter.hasNext()){
					 Map.Entry<String, String> entry = (Map.Entry<String, String>)iter.next();
					 ethernet.add(new DefaultMutableTreeNode(entry.getKey() + ": " + entry.getValue()));
				 }
				 root2.add(ethernet);
				 
				 DefaultTreeModel model = (DefaultTreeModel)tree.getModel();
				 model.setRoot(root2);
				 
				 switch (pr.m.get("Type")) {
				case "ARP (0x0806)":
					DefaultMutableTreeNode arp = DrawARPTree();
					root2.add(arp);
					model.setRoot(root2);
					expandAllNodes(tree, 0, tree.getRowCount());
					break;
				case "IPv4 (0x0800)":
					DefaultMutableTreeNode ip = DrawIPTree();
					root2.add(ip);
					switch (pr.ip.m.get("Protocol")) {
					case "TCP (6)":
						DefaultMutableTreeNode tcp = DrawTCPTree();
						root2.add(tcp);
						break;
					case "UDP (17)":
						DefaultMutableTreeNode udp = DrawUDPTree();
						root2.add(udp);
						switch(pr.ip.udp.m.get("Source Port")){
						case "68":
						case "67":
							DefaultMutableTreeNode bootp = DrawBOOTPTree();
							root2.add(bootp);
							break;
						default:
							break;
						}
						switch(pr.ip.udp.m.get("Destination Port")){
						case "53":
							DefaultMutableTreeNode dns = DrawDNSTree();
							root2.add(dns);
							break;
						case "161":
						case "162":
							DefaultMutableTreeNode snmp = DrawSNMPTree();
							root2.add(snmp);
							break;
						default:
							break;
						}
						break;
					case "ICMP (1)":
						DefaultMutableTreeNode icmp = DrawICMPTree();
						root2.add(icmp);
						break;
					case "IGMP (2)":
						DefaultMutableTreeNode igmp = DrawIGMPTree();
						root2.add(igmp);
						break;
					default:
						break;
					}
					model.setRoot(root2);
					expandAllNodes(tree, 0, tree.getRowCount());
					break;
				default:
					break;
				}
				 DefaultTreeCellRenderer render = (DefaultTreeCellRenderer)tree.getCellRenderer();
				 render.setLeafIcon(null);
				 render.setClosedIcon(null);
				 render.setOpenIcon(null);
			 }
			 
		 }
	 }
	 public DefaultMutableTreeNode DrawARPTree(){
		 DefaultMutableTreeNode arp = new DefaultMutableTreeNode("Address Resolution Protocol");
		 
		 Iterator iter = pr.arp.m.entrySet().iterator();
		 while(iter.hasNext()){
			 Map.Entry<String, String> entry = (Map.Entry<String, String>)iter.next();
			 arp.add(new DefaultMutableTreeNode(entry.getKey() + ": " + entry.getValue()));
		 }
		 return arp;
	 }
	 
	 public DefaultMutableTreeNode DrawDNSTree(){
		 DefaultMutableTreeNode dns = new DefaultMutableTreeNode("Domain Name System");
		 
		 Iterator iter = pr.ip.udp.dns.m.entrySet().iterator();
		 while(iter.hasNext()){
			 Map.Entry<String,String> entry = (Map.Entry<String,String>)iter.next();
			 dns.add(new DefaultMutableTreeNode(entry.getKey() + ":" + entry.getValue()));
		 }
		 return dns;
	 }
	 
	 public DefaultMutableTreeNode DrawSNMPTree(){
		 DefaultMutableTreeNode snmp = new DefaultMutableTreeNode("Simple Network Management Protocol");
		 
		 Iterator iter = pr.ip.udp.snmp.m.entrySet().iterator();
		 while(iter.hasNext()){
			 Map.Entry<String,String> entry = (Map.Entry<String,String>)iter.next();
			 if(entry.getKey() == "data"){
			 	 snmp.add(DrawDataTree(entry.getValue()));
			 }
			 else
				 snmp.add(new DefaultMutableTreeNode(entry.getKey() + ":" + entry.getValue()));
		 }
		 return snmp;
	 }
	 
	 public DefaultMutableTreeNode DrawIPTree(){
		 DefaultMutableTreeNode ip = new DefaultMutableTreeNode("Internet Protocol");
		 
		 Iterator iter = pr.ip.m.entrySet().iterator();
		 while(iter.hasNext()){
			 Map.Entry<String, String> entry = (Map.Entry<String, String>)iter.next();
			 ip.add(new DefaultMutableTreeNode(entry.getKey() + ": " + entry.getValue()));
		 }
		 
		 if(pr.ip.m.get("Protocol") == "IGMP (2)"){
			 ip.add(DrawIGMPOptionsTree());
		 }
		 return ip;
	 }
	 
	 public DefaultMutableTreeNode DrawTCPTree(){
		 DefaultMutableTreeNode tcp = new DefaultMutableTreeNode("Transmission Control Protocol");
		 
		 Iterator iter = pr.ip.tcp.m.entrySet().iterator();
		 while(iter.hasNext()){
			 Map.Entry<String, String> entry = (Map.Entry<String, String>)iter.next();
			 if(entry.getKey() == "Window Size"){
				 tcp.add(DrawTCPFlagsTree());
			 }
			 tcp.add(new DefaultMutableTreeNode(entry.getKey() + ": " + entry.getValue()));
		 }
		 return tcp;
	 }
	 
	 public DefaultMutableTreeNode DrawUDPTree(){
		 DefaultMutableTreeNode udp = new DefaultMutableTreeNode("User Datagram Protocol");
		 Iterator iter = pr.ip.udp.m.entrySet().iterator();
		 while(iter.hasNext()){
			 Map.Entry<String, String> entry = (Map.Entry<String, String>)iter.next();
			 udp.add(new DefaultMutableTreeNode(entry.getKey() + ": " + entry.getValue()));
		 }
		 return udp;
	 }
	 
	 public DefaultMutableTreeNode DrawICMPTree(){
		 DefaultMutableTreeNode icmp = new DefaultMutableTreeNode("Internet Control Message Protocol");
		 Iterator iter = pr.ip.icmp.m.entrySet().iterator();
		 while(iter.hasNext()){
			 Map.Entry<String, String> entry =(Map.Entry<String, String>)iter.next();
			 icmp.add(new DefaultMutableTreeNode(entry.getKey() + ": " + entry.getValue()));
		 }
		 return icmp;
	 }
	 
	 public DefaultMutableTreeNode DrawIGMPTree(){
		 DefaultMutableTreeNode  igmp = new DefaultMutableTreeNode("Internet Group Management Protocol");
		 Iterator iter = pr.ip.igmp.m.entrySet().iterator();
		 while(iter.hasNext()){
			 Map.Entry<String, String> entry =(Map.Entry<String, String>)iter.next();
			 igmp.add(new DefaultMutableTreeNode(entry.getKey() + ": " + entry.getValue()));
		 }

		 return igmp;
	 }
	 
	 public DefaultMutableTreeNode DrawIGMPOptionsTree(){
		 DefaultMutableTreeNode igmpOptions = new DefaultMutableTreeNode("Options: (4 bytes)");
		 DefaultMutableTreeNode routerAlert = new DefaultMutableTreeNode("Router Alert (4 bytes)");
		 
		 Iterator iter = pr.ip.igmpOptions.m.entrySet().iterator();
		 while(iter.hasNext()){
			 Map.Entry<String, String> entry =(Map.Entry<String, String>)iter.next();
			 routerAlert.add(new DefaultMutableTreeNode(entry.getKey() + ": " + entry.getValue()));
		 }
		 igmpOptions.add(routerAlert);
		 
		 return igmpOptions;
	 }
	 
	 public DefaultMutableTreeNode DrawTCPFlagsTree(){
		 DefaultMutableTreeNode flags = new DefaultMutableTreeNode("Flags");
		 
		 Iterator iter = pr.ip.tcp.flags.m.entrySet().iterator();
		 while(iter.hasNext()){
			 Map.Entry<String, String> entry = (Map.Entry<String, String>)iter.next();
			 flags.add(new DefaultMutableTreeNode(entry.getKey() + ": " + entry.getValue()));
		 }
		 return flags;
	 }
	 
	 public DefaultMutableTreeNode DrawDataTree(String str){
		 DefaultMutableTreeNode variable = new DefaultMutableTreeNode("data: "+str);
		 
		 Iterator iter = pr.ip.udp.snmp.pdu.m.entrySet().iterator();
		 while(iter.hasNext()){
			 Map.Entry<String, String> entry = (Map.Entry<String, String>)iter.next();
			 if(entry.getKey() == "variable-bindings"){
				 variable.add(DrawVBTree());
			 }
			 else
				 variable.add(new DefaultMutableTreeNode(entry.getKey() + "：" +entry.getValue()));
		 }
		 return variable;
	 }
	 
	 public DefaultMutableTreeNode DrawVBTree(){
		 DefaultMutableTreeNode vb = new DefaultMutableTreeNode("variable-bindings : item");
		 
		 Iterator iter = pr.ip.udp.snmp.pdu.vb.m.entrySet().iterator();
		 while(iter.hasNext()){
			 Map.Entry<String, String> entry = (Map.Entry<String, String>)iter.next();
			 //if(entry.getKey() == "variable-bindings")
				 vb.add(new DefaultMutableTreeNode(entry.getKey() + "：" +entry.getValue()));
		 }
		 return vb;
	 }
	 
	 public DefaultMutableTreeNode DrawBOOTPTree(){
		 DefaultMutableTreeNode bootp = new DefaultMutableTreeNode("Bootstrap Protocol");
		 
		 Iterator iter = pr.ip.udp.bootp.m.entrySet().iterator();
		 while(iter.hasNext()){
			 Map.Entry<String, String> entry = (Map.Entry<String, String>)iter.next();
			 if(entry.getKey() == "Padding"){
				 for(BOOTPOption option: pr.ip.udp.bootp.bootpOptions){
					 DefaultMutableTreeNode optionTree = new DefaultMutableTreeNode("Option: " + option.m.get("Option"));
					 Iterator iter1 = option.m.entrySet().iterator();
					 while(iter1.hasNext()){
						 Map.Entry<String, String> entry1 = (Map.Entry<String, String>)iter1.next();
						 if(entry1.getKey() == "Option") continue;
						 optionTree.add(new DefaultMutableTreeNode(entry1.getKey() + ": " + entry1.getValue()));
					 }
					 bootp.add(optionTree);
				 }
			 }
			 bootp.add(new DefaultMutableTreeNode(entry.getKey() + ": " + entry.getValue()));
		 }
		 return bootp;
	 }
	 
	 private void LoadFile(String path){
		 pr = new PackageReader(path);
	 }
	 
	 private void expandAllNodes(JTree tree, int startIndex, int rowCount){
		 //扩展树的每一行的内容
		 for(int i=startIndex; i<rowCount; i++){
			 tree.expandRow(i);
		 }
		 if(tree.getRowCount()!=rowCount){
		        expandAllNodes(tree, rowCount, tree.getRowCount());
		    }
	 }
}
