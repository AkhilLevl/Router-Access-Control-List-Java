
public class StandardACL {
	public  String Permission;
	public  String sourceAddress;
	public  String sourceMask;
	
	public StandardACL(String Permission, String sourceAddress, String sourceMask)
	{
		this.Permission = Permission;
		this.sourceAddress = sourceAddress;
		this.sourceMask = sourceMask;
	}
}
