

$definitionCode = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public class StlParser
{
    [DllImport("Crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    static extern bool CryptQueryObject(
    uint dwObjectType,
    IntPtr pvObject,
    //[MarshalAs(UnmanagedType.LPWStr)] string pvObject,
    uint dwExpectedContentTypeFlags,
    uint dwExpectedFormatTypeFlags,
    uint dwFlags,
    out uint pdwMsgAndCertEncodingType,
    out uint pdwContentType,
    out uint pdwFormatType,
    out IntPtr phCertStore,
    out IntPtr phMsg,
    out IntPtr ppvContext);

    [DllImport("Crypt32.dll", SetLastError = true)]
    public static extern IntPtr CertEnumCTLsInStore(IntPtr hCertStore, IntPtr pPrevCtl);

    [DllImport("Crypt32.dll", SetLastError = true)]
    public static extern bool CertCloseStore(IntPtr hCertStore, uint dwFlags);

    public struct CTL_CONTEXT
    {
        public uint dwMsgAndCertEncodingType;
        public IntPtr pbCtlEncoded;
        public uint cbCtlEncoded;
        public IntPtr pCtlInfo;
        public IntPtr hCertStore;
        public IntPtr hCryptMsg;
        public IntPtr pbCtlContent;
        public uint cbCtlContent;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CTL_INFO
    {
        public uint dwVersion;
        public CTL_USAGE SubjectUsage;
        public CRYPT_DATA_BLOB ListIdentifier;
        public CRYPT_INTEGER_BLOB SequenceNumber;
        public FILETIME ThisUpdate;
        public FILETIME NextUpdate;
        public CRYPT_ALGORITHM_IDENTIFIER SubjectAlgorithm;
        public uint cCTLEntry;
        public IntPtr rgCTLEntry;
        public uint cExtension;
        public IntPtr rgExtension;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CTL_USAGE
    {
        public uint cUsageIdentifier;
        public IntPtr rgpszUsageIdentifier;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CTL_ENTRY
    {
        public CRYPT_DATA_BLOB SubjectIdentifier;
        public uint cAttribute;
        public IntPtr rgAttribute;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_DATA_BLOB
    {
        public uint cbData;
        public IntPtr pbData;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_INTEGER_BLOB
    {
        public uint cbData;
        public IntPtr pbData;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_ALGORITHM_IDENTIFIER
    {
        public IntPtr pszObjId;
        public CRYPT_OBJID_BLOB Parameters;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_OBJID_BLOB
    {
        public uint cbData;
        public IntPtr pbData;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FILETIME
    {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
    }

    public static uint CERT_QUERY_OBJECT_FILE = 1;
    public static uint CERT_QUERY_OBJECT_BLOB = 2;

    public static List<string> parseMemory(byte[] regData)
    {
        uint dwEncodingType;
        uint dwContentType;
        uint dwFormatType;
        IntPtr hCertStore = IntPtr.Zero;
        IntPtr hMsg = IntPtr.Zero;
        IntPtr ppvContext = IntPtr.Zero;

        IntPtr cryptoBlop = Marshal.AllocHGlobal(regData.Length);
        Marshal.Copy(regData, 0, cryptoBlop, regData.Length);

        CRYPT_DATA_BLOB dataBlop = new CRYPT_DATA_BLOB();
        dataBlop.cbData = (uint)regData.Length;
        dataBlop.pbData = cryptoBlop;

        IntPtr dataBlopPtr = Marshal.AllocHGlobal(Marshal.SizeOf(dataBlop));
        Marshal.StructureToPtr(dataBlop, dataBlopPtr, false);

        bool bResult = CryptQueryObject(
            (uint)CERT_QUERY_OBJECT_BLOB,
            dataBlopPtr,
            (uint)16382, //CERT_QUERY_CONTENT_FLAG_ALL,
            (uint)14, //CERT_QUERY_FORMAT_FLAG_ALL,
            0,
            out dwEncodingType,
            out dwContentType,
            out dwFormatType,
            out hCertStore,
            out hMsg,
            out ppvContext);

        IntPtr pContext = IntPtr.Zero;
        List<string> result = new List<string>();

        try
        {
            while ((pContext = CertEnumCTLsInStore(hCertStore, pContext)) != IntPtr.Zero)
            {
                CTL_CONTEXT context = (CTL_CONTEXT)Marshal.PtrToStructure(pContext, typeof(CTL_CONTEXT));
                CTL_INFO ctl_info = (CTL_INFO)Marshal.PtrToStructure(context.pCtlInfo, typeof(CTL_INFO));

                if (ctl_info.cCTLEntry > 0)
                {
                    for (int i = 0; i < ctl_info.cCTLEntry; i++)
                    {
                        CTL_ENTRY entry = (CTL_ENTRY)Marshal.PtrToStructure(ctl_info.rgCTLEntry + i * Marshal.SizeOf(typeof(CTL_ENTRY)), typeof(CTL_ENTRY));
                        byte[] bytes = new byte[entry.SubjectIdentifier.cbData];
                        Marshal.Copy(entry.SubjectIdentifier.pbData, bytes, 0, bytes.Length);
                        result.Add(BitConverter.ToString(bytes).Replace("-", string.Empty));
                    }
                }
            }
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(cryptoBlop);
            Marshal.FreeHGlobal(dataBlopPtr);
            CertCloseStore(hCertStore, 0);
        }
    }

    public static List<string> parse(string unicodePath)
    {
        uint dwEncodingType;
        uint dwContentType;
        uint dwFormatType;
        IntPtr hCertStore = IntPtr.Zero;
        IntPtr hMsg = IntPtr.Zero;
        IntPtr ppvContext = IntPtr.Zero;

        IntPtr pUnicodePath = Marshal.StringToHGlobalUni(unicodePath);

        bool bResult = CryptQueryObject(
            (uint)CERT_QUERY_OBJECT_FILE,
            pUnicodePath,
            (uint)16382, //CERT_QUERY_CONTENT_FLAG_ALL,
            (uint)14, //CERT_QUERY_FORMAT_FLAG_ALL,
            0,
            out dwEncodingType,
            out dwContentType,
            out dwFormatType,
            out hCertStore,
            out hMsg,
            out ppvContext);

        IntPtr pContext = IntPtr.Zero;
        List<string> result = new List<string>();

        try
        {
            while ((pContext = CertEnumCTLsInStore(hCertStore, pContext)) != IntPtr.Zero)
            {
                CTL_CONTEXT context = (CTL_CONTEXT)Marshal.PtrToStructure(pContext, typeof(CTL_CONTEXT));
                CTL_INFO ctl_info = (CTL_INFO)Marshal.PtrToStructure(context.pCtlInfo, typeof(CTL_INFO));

                if (ctl_info.cCTLEntry > 0)
                {
                    for (int i = 0; i < ctl_info.cCTLEntry; i++)
                    {
                        CTL_ENTRY entry = (CTL_ENTRY)Marshal.PtrToStructure(ctl_info.rgCTLEntry + i * Marshal.SizeOf(typeof(CTL_ENTRY)), typeof(CTL_ENTRY));
                        byte[] bytes = new byte[entry.SubjectIdentifier.cbData];
                        Marshal.Copy(entry.SubjectIdentifier.pbData, bytes, 0, bytes.Length);
                        result.Add(BitConverter.ToString(bytes).Replace("-", string.Empty));
                    }
                }
            }
            return result;
        }
        finally
        {
            CertCloseStore(hCertStore, 0);
        }
    }
}
"@

if ("StlParser" -as [type]) {
   Write-Verbose "StlParser already loaded";
}
else {
   Add-Type -TypeDefinition $definitionCode -Language CSharp;
}

function Get-vlCertificateTrustListFromBytes {
   [CmdletBinding()]
   param (
      $bytes
   )

   #Check if byte array is not null
   if ($bytes.Length -eq 0) {
      Write-Error "Invalid byte array"
      return
   }

   $listOfTrustedCerts = @()

   try {
      $listOfTrustedCerts = [StlParser]::parseMemory($bytes);
   }
   catch {
      Write-Error "Error while parsing file"
      return
   }

   return $listOfTrustedCerts
}

function Get-vlCertificateTrustListFromFile {
   [CmdletBinding()]
   param (
      [Parameter()]
      [string]
      $path
   )

   #Check if file exists
   if (!(Test-Path $path)) {
      Write-Error "File not found"
      return
   }

   $listOfTrustedCerts = @()

   try {
      $listOfTrustedCerts = [StlParser]::parse($path);
   }
   catch {
      Write-Error "Error while parsing file"
      return
   }

   return $listOfTrustedCerts
}

function Expand-vlCabFile {
   param(
      [string]$CabFilePath,
      [string]$DestinationFilePath
   )

   $command = "expand.exe `"$CabFilePath`" `"$DestinationFilePath`""
   $result = Invoke-Expression $command
}