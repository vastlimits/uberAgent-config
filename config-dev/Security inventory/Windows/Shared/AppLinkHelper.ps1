#Requires -Version 3.0

<#
This PowerShell code loads a C# class called AppLinkHelper into the PowerShell environment that is used to determine file and log associations in Windows.
The class contains methods and enumerations that use the AssocQueryString function from Shlwapi.dll.
#>


$getLinkedAppCSharp = @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class AppLinkHelper
{
    // Declare the DLL function
    [DllImport("Shlwapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern uint AssocQueryString(AssocF flags, AssocStr str, string pszAssoc, string pszExtra, [Out] StringBuilder pszOut, ref uint pcchOut);

    // Public method to get associated command for a file extension
    public static string AssocQueryString(string extension)
    {
        return AssocQueryString(AssocF.None, AssocStr.Executable, extension);
    }

    // Internal method to call the DLL function and process its return
    internal static string AssocQueryString(AssocF assocF, AssocStr association, string assocString)
    {
        uint length = 0;
        uint ret = AssocQueryString(assocF, association, assocString, null, null, ref length);

        if (ret != 1) // Expected S_FALSE
        {
            return null;
        }

        // Create a StringBuilder with the required length
        var sb = new StringBuilder((int)length);

        ret = AssocQueryString(assocF, association, assocString, null, sb, ref length);

        if (ret != 0) // Expected S_OK
        {
            return null;
        }

        return sb.ToString();
    }

    // Define AssocF enum
    [Flags]
    internal enum AssocF : uint
    {
        None = 0,
        Init_NoRemapCLSID = 0x1,
        Init_ByExeName = 0x2,
        Open_ByExeName = 0x2,
        Init_DefaultToStar = 0x4,
        Init_DefaultToFolder = 0x8,
        NoUserSettings = 0x10,
        NoTruncate = 0x20,
        Verify = 0x40,
        RemapRunDll = 0x80,
        NoFixUps = 0x100,
        IgnoreBaseClass = 0x200,
        Init_IgnoreUnknown = 0x400,
        Init_FixedProgId = 0x800,
        IsProtocol = 0x1000,
        InitForFile = 0x2000,
    }

    // Define AssocStr enum
    internal enum AssocStr
    {
        Command = 1,
        Executable,
        FriendlyDocName,
        FriendlyAppName,
        NoOpen,
        ShellNewValue,
        DDECommand,
        DDEIfExec,
        DDEApplication,
        DDETopic,
        InfoTip,
        QuickTip,
        TileInfo,
        ContentType,
        DefaultIcon,
        ShellExtension,
        DropTarget,
        DelegateExecute,
        SupportedUriProtocols,
        Max,
    }
}
"@


# Check if the AppLinkHelper class is already loaded and if not, load it.

if ("AppLinkHelper" -as [type]) {
    Write-Verbose "AppLinkHelper already loaded";
}
else {
    try {
        Add-Type -TypeDefinition $getLinkedAppCSharp -Language CSharp;
    }
    catch {
        $errorMsg = "Failed to load AppLinkHelper: " + $_.Exception.Message
        Write-Error $errorMsg ;
    }
}