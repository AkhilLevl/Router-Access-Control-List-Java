import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Scanner;

public class ProcessingACL {

	public static File ACLInputFile;
	public static File IPAddressFile;
	public static ArrayList <String []> IPAddressList;
	public static ArrayList <StandardACL> standardACLList;
	public static ArrayList <ExtendedACL> extendedACLList;
	public static ArrayList <String[]> outputList;
	public static boolean isError = false;
	
	public static void main(String[] args) throws FileNotFoundException, IOException 
	{
		ProcessingACL ACLObj = new ProcessingACL();
		Scanner reader = new Scanner(System.in);
		System.out.println("1 for Standard ACL\n2 for Extended ACL\nEnter your input: ");
		int ACLType = reader.nextInt();
		if(ACLType == 1)
		{
			ACLInputFile = new File("/home/senthan/Downloads/StandardACL.txt"); // set path to input file
			System.out.println(ACLInputFile);
		}
		else if(ACLType == 2)
		{
			ACLInputFile = new File("/home/senthan/Downloads/ExtendedACL.txt"); // set path to input file
			System.out.println(ACLInputFile);
		}
		else
		{
			System.out.println("Wrong Input");
		}
		IPAddressFile = new File("/home/senthan/Downloads/IPAddresses.txt"); // set path to input file
		
		String selectedACL = ACLObj.Reading();  // function to read input IP file
		ACLObj.Computing(selectedACL);          // function to compute ACL
		reader.close();
	}
	
	private String Reading() throws FileNotFoundException, IOException // reads the IP address file to check if standard   
	{                                                                  // or extended ACL is required 
		IPAddressList = new ArrayList < String []> ();
		standardACLList = new ArrayList <StandardACL> ();
		extendedACLList = new ArrayList <ExtendedACL> ();
		try (BufferedReader br = new BufferedReader(new FileReader(IPAddressFile)))
        {
			String lines;
			while ((lines = br.readLine()) != null)
            {
				lines = lines.trim().replaceAll(" +", " ");
				String [] PacketLineList = lines.split(" ");
				IPAddressList.add(PacketLineList);
            }
        }
        String selectedACL = "";
        try (BufferedReader br = new BufferedReader(new FileReader(ACLInputFile)))
        {
        	String ACLLine;
        	int LineNumber = 0;
            while ((ACLLine = br.readLine()) != null)
            {
        		ACLLine = ACLLine.trim().replaceAll(" +", " ");
        		String [] LineList = ACLLine.split(" ");
        		if(LineNumber == 0)
        		{
        			if(Integer.valueOf(LineList[1]) > 0 && Integer.valueOf(LineList[1]) < 100)
        			{
        				System.out.println("\nStandard ACL");
        				selectedACL = "StandardACL";
        			}
        			else if(Integer.valueOf(LineList[1]) >= 100 && Integer.valueOf(LineList[1]) < 200)
        			{
        				System.out.println("\nExtended ACL");
        				selectedACL = "ExtendedACL";
        			}
        		}
        		if(selectedACL.equals("StandardACL"))
        		{
        			if(LineList[2].toLowerCase().contains("deny") || LineList[2].toLowerCase().contains("permit"))
        			{
        				if(LineList[3].equals("any"))
        					LineList[3] = "255.255.255.255";
        				if(LineList[4].equals("any") || LineList.length == 4)
        					LineList[4] = "255.255.255.255";
        				StandardACL standardACLRecord = new StandardACL(LineList[2], LineList[3], LineList[4]);
        				standardACLList.add(standardACLRecord);
        			}
        		}
        		else if(selectedACL.equals("ExtendedACL"))
        		{

        			if(LineList[2].toLowerCase().contains("deny") || LineList[2].toLowerCase().contains("permit"))
        			{
        				if(LineList[4].equals("any"))
        					LineList[4] = "255.255.255.255";
        				if(LineList[5].equals("any"))
        					LineList[5] = "255.255.255.255";
        				if(LineList[6].equals("any"))
        					LineList[6] = "255.255.255.255";
        				if(LineList[7].equals("any"))
        					LineList[7] = "255.255.255.255";
        				ExtendedACL extendedACLRecord = new ExtendedACL(LineList[2], LineList[4], LineList[5], LineList[6], LineList[7]);
        				extendedACLList.add(extendedACLRecord);
        			}
        		}
        		LineNumber ++;
            }
        }
        catch (Exception e)
        {
        	
        }
        return selectedACL;
	}
	
	public void Computing(String selectedACL) 
	{
		outputList = new ArrayList <String []> ();
		if(selectedACL.equals("StandardACL"))
			StandardACL();
		else if(selectedACL.equals("ExtendedACL"))
			ExtendedACL();
	}
	
	public static void StandardACL() // reads the ACL and addresses and prints result
	{
		for(String [] PacketLineList : IPAddressList)
		{
			Boolean ISDenied = true;
			for(StandardACL standardACLRecord : standardACLList)
			{		
				String sourceNetworkAddrACL = getAddr(standardACLRecord.sourceAddress , standardACLRecord.sourceMask);
				String sourceNetworkAddrPacket = getAddr(PacketLineList[0],standardACLRecord.sourceMask);
				if(sourceNetworkAddrACL.equals(sourceNetworkAddrPacket))
				{
					if(standardACLRecord.Permission.toLowerCase().equals("deny"))
					{
						ISDenied = ISDenied && true;
						break;
					}
					else if(standardACLRecord.Permission.toLowerCase().equals("permit"))
					{
						ISDenied = ISDenied && false;
						break;
					}
					
				}
			}
			String[] Display = new String [3];
			Display[0] = PacketLineList[0];
			Display[1] = PacketLineList[1];
			if(ISDenied)
			{
				Display[2] = "Deny";
			}
			else
			{
				Display[2] = "Permit";
			}
			outputList.add(Display);
			
		}
		for(String[] Display : outputList)
			System.out.println(Display[0]+"\t"+Display[1]+"\t"+Display[2]);
	}
	
	public static String getAddr(String IPAddress , String Mask) // gets the correct network address
	{
		String [] IPComponents = IPAddress.split("\\.");
		String [] maskComponents = Mask.split("\\.");
		String [] networkAddress = new String [4];
		for(int i = 0; i < maskComponents.length; i++)
		{
			if(maskComponents[i].equals("0"))
			{
				maskComponents[i] = "1";
			}
			else if(maskComponents[i].equals("255"))
			{
				maskComponents[i] = "0";
			}
		}
		for(int i = 0; i < IPComponents.length; i++)
		{
			networkAddress[i] = String.valueOf(Integer.valueOf(IPComponents[i]) * Integer.valueOf(maskComponents[i]));
		}
		
		return networkAddress[0]+"."+networkAddress[1]+"."+networkAddress[2]+"."+networkAddress[3];
	}
	
	
	public static void ExtendedACL()  // reads the ACL and addresses and prints result
	{
		for(String [] PacketLineList : IPAddressList)
		{
			Boolean ISDenied = true;
			for(ExtendedACL extendedACLRecord : extendedACLList)
			{		
				String sourceNetworkAddrACL = getAddr(extendedACLRecord.sourceAddress , extendedACLRecord.sourceMask);
				String sourceNetworkAddrPacket = getAddr(PacketLineList[0],extendedACLRecord.sourceMask);
				String dstNetworkAddrACL = getAddr(extendedACLRecord.destinationAddr , extendedACLRecord.destinationMask);
				String dstNetworkAddrPacket = getAddr(PacketLineList[1],extendedACLRecord.destinationMask);
				if(sourceNetworkAddrACL.equals(sourceNetworkAddrPacket) && dstNetworkAddrACL.equals(dstNetworkAddrPacket))
				{
					if(extendedACLRecord.Permission.toLowerCase().equals("deny"))
					{
						ISDenied = ISDenied && true;
						break;
					}
					else if(extendedACLRecord.Permission.toLowerCase().equals("permit"))
					{
						ISDenied = ISDenied && false;
						break;
					}
					
				}
			}
			String[] Display = new String [3];
			Display[0] = PacketLineList[0];
			Display[1] = PacketLineList[1];
			if(ISDenied)
			{
				Display[2] = "Deny";
			}
			else
			{
				Display[2] = "Permit";
			}
			outputList.add(Display);
			
		}
		for(String[] Display : outputList)
			System.out.println(Display[0]+"\t"+Display[1]+"\t"+Display[2]);
	}
	
}
