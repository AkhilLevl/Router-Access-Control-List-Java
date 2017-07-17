
public class ExtendedACL {
	public  String Permission;
	public  String sourceAddress;
	public  String sourceMask;
	public  String destinationAddr;
	public  String destinationMask;
	
	public ExtendedACL(String Permission, String sourceAddress, String sourceMask, String destinationAddr, String destinationMask)
	{
		this.Permission = Permission;
		this.sourceAddress = sourceAddress;
		this.sourceMask = sourceMask;
		this.destinationAddr = destinationAddr;
		this.destinationMask = destinationMask;
	}
}
