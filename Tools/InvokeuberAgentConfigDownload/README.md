# InvokeuberAgentConfigDownload

## Description

While the configuration for uberAgent UXM remains relatively static, the configuration for uberAgent ESA changes daily due to regular updates to the included Sigma rules.

To make your life easier, we provide a PowerShell script that automates the configuration file pulling, filtering, and bundling.

You can find examples in the [Syntax and Examples](#syntax-and-examples) section for the most common use-cases:
- **Example 1**: you have a customized `uberAgent.conf` that should persist, but all other configuration files should be on the latest version available on GitHub.
- **Example 2**: you applied several customizations in the configuration files that should persist, but all TDE rules and SCI tests should be on the latest version available on GitHub.
- **Example 3**: you want the latest TDE rules from GitHub with a few exceptions.

## Development
The script covers the most common use-cases. If you want to see examples for other use-cases or have ideas to extend the script, please do not hesitate to create a GitHub issue or a pull request. Or contact us via [support@uberagent.com](mailto:support@uberagent.com).

## Syntax and Examples

```
NAME
    InvokeuberAgentConfigDownload.ps1
    
SYNOPSIS
    Downloads the uberAgent configuration from a configurable GitHub branch, applies excludes and includes, creates a 
    configuration archive, and copies the result to a target folder.
    
    
SYNTAX
    InvokeuberAgentConfigDownload.ps1
     [[-Branch] <String>] [-TargetDirectory] <String> [[-Excludes] <String[]>] [[-Includes] <String[]>] 
    [[-uAConfigArchive] <Boolean>] [[-ForceVersionUpdate] <Boolean>] [[-RepoUrl] <String>] [<CommonParameters>]
    
    
DESCRIPTION
    

PARAMETERS
    -Branch <String>
        The GitHub branch that should be cloned. A branch is equivalent to an uberAgent version. Mandatory parameter.
        
        Required?                    false
        Position?                    1
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -TargetDirectory <String>
        Path the files should be copied to. Only full paths are supported. Do not use relative paths. Mandatory 
        parameter.
        
        Required?                    true
        Position?                    2
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -Excludes <String[]>
        List of files not downloaded. Wildcards are supported. Use it when you want to persist existing config files. 
        Excludes takes precedence over includes.
        
        Required?                    false
        Position?                    3
        Default value                @()
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -Includes <String[]>
        List of files to be copied. Wildcards are supported. Use it when you want to download only a subset from 
        GitHub. Excludes takes precedence over includes.
        
        Required?                    false
        Position?                    4
        Default value                @()
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -uAConfigArchive <Boolean>
        Creates an uberAgent.uAConfig archive from the target directory. The uberAgent.uAConfig is placed in the root 
        of the target folder.
        The archive is downloaded by the endpoint agents and applied if meaningful changes are found. See 
        https://uberagent.com/docs/uberagent/latest/advanced-topics/auto-application-of-configuration-changes/.
        Default is true.
        
        Required?                    false
        Position?                    5
        Default value                True
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -ForceVersionUpdate <Boolean>
        This updates the version setting in the uberAgent.conf so that the endpoint agent is forced to restart and 
        update the config even if there were no meaningful changes.
        Requires an existing uberAgent.conf in the target directory.
        Default is false.
        
        Required?                    false
        Position?                    6
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -RepoUrl <String>
        uberAgent GitHub repository URL. Typically there is no need to change this parameter.
        Default is "https://github.com/vastlimits/uberAgent-config"
        
        Required?                    false
        Position?                    7
        Default value                https://github.com/vastlimits/uberAgent-config
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see 
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216). 
    
INPUTS
    
OUTPUTS
    
    -------------------------- EXAMPLE 1 --------------------------
    
    PS C:\>.\InvokeuberAgentConfigDownload.ps1 -Branch "7.1" -TargetDirectory "\\server\share\uberAgentConfig" 
    -Excludes "uberAgent.conf" -uAConfigArchive $true -ForceVersionUpdate $true
    
    Download everything except uberAgent.conf. Create an uberAgent.uAConfig archive and update the version string to 
    force the endpoint agent to apply the archive.
    
    
    
    
    -------------------------- EXAMPLE 2 --------------------------
    
    PS C:\>.\InvokeuberAgentConfigDownload.ps1 -Branch "7.1" -TargetDirectory "\\server\share\uberAgentConfig" 
    -Includes "uberAgent-ESA-am-*.conf", "uberAgent-ESA-si-*.conf", "Security inventory", "Security inventory\*"
    
    Download only TDE rules and everything relevant to SCI tests
    
    
    
    
    -------------------------- EXAMPLE 3 --------------------------
    
    PS C:\>.\InvokeuberAgentConfigDownload.ps1 -Branch "7.1" -TargetDirectory "\\server\share\uberAgentConfig" 
    -Includes "uberAgent-ESA-am-*.conf", -Excludes "uberAgent-ESA-am-sigma-informational-*.conf"
    
    Download all TDE rules except the informational ones from Sigma
    
    
    
    
    
RELATED LINKS
    https://github.com/vastlimits/uberAgent-config
    uberagent.com
```