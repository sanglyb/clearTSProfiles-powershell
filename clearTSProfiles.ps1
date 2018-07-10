Function Set-Owner {
    <#
        .SYNOPSIS
            Changes owner of a file or folder to another user or group.

        .DESCRIPTION
            Changes owner of a file or folder to another user or group.

        .PARAMETER Path
            The folder or file that will have the owner changed.

        .PARAMETER Account
            Optional parameter to change owner of a file or folder to specified account.

            Default value is 'Builtin\Administrators'

        .PARAMETER Recurse
            Recursively set ownership on subfolders and files beneath given folder.

        .NOTES
            Name: Set-Owner
            Author: Boe Prox
            Version History:
                 1.0 - Boe Prox
                    - Initial Version

        .EXAMPLE
            Set-Owner -Path C:\temp\test.txt

            Description
            -----------
            Changes the owner of test.txt to Builtin\Administrators

        .EXAMPLE
            Set-Owner -Path C:\temp\test.txt -Account 'Domain\bprox

            Description
            -----------
            Changes the owner of test.txt to Domain\bprox

        .EXAMPLE
            Set-Owner -Path C:\temp -Recurse 

            Description
            -----------
            Changes the owner of all files and folders under C:\Temp to Builtin\Administrators

        .EXAMPLE
            Get-ChildItem C:\Temp | Set-Owner -Recurse -Account 'Domain\bprox'

            Description
            -----------
            Changes the owner of all files and folders under C:\Temp to Domain\bprox
    #>
    [cmdletbinding(
        SupportsShouldProcess = $True
    )]
    Param (
        [parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Alias('FullName')]
        [string[]]$Path,
        [parameter()]
        [string]$Account = 'Builtin\Administrators',
        [parameter()]
        [switch]$Recurse
    )
    Begin {
        #Prevent Confirmation on each Write-Debug command when using -Debug
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
        Try {
            [void][TokenAdjuster]
        } Catch {
            $AdjustTokenPrivileges = @"
            using System;
            using System.Runtime.InteropServices;

             public class TokenAdjuster
             {
              [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
              internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
              ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
              [DllImport("kernel32.dll", ExactSpelling = true)]
              internal static extern IntPtr GetCurrentProcess();
              [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
              internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr
              phtok);
              [DllImport("advapi32.dll", SetLastError = true)]
              internal static extern bool LookupPrivilegeValue(string host, string name,
              ref long pluid);
              [StructLayout(LayoutKind.Sequential, Pack = 1)]
              internal struct TokPriv1Luid
              {
               public int Count;
               public long Luid;
               public int Attr;
              }
              internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
              internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
              internal const int TOKEN_QUERY = 0x00000008;
              internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
              public static bool AddPrivilege(string privilege)
              {
               try
               {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_ENABLED;
                retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
               }
               catch (Exception ex)
               {
                throw ex;
               }
              }
              public static bool RemovePrivilege(string privilege)
              {
               try
               {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_DISABLED;
                retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
               }
               catch (Exception ex)
               {
                throw ex;
               }
              }
             }
"@
            Add-Type $AdjustTokenPrivileges
        }

        #Activate necessary admin privileges to make changes without NTFS perms
        [void][TokenAdjuster]::AddPrivilege("SeRestorePrivilege") #Necessary to set Owner Permissions
        [void][TokenAdjuster]::AddPrivilege("SeBackupPrivilege") #Necessary to bypass Traverse Checking
        [void][TokenAdjuster]::AddPrivilege("SeTakeOwnershipPrivilege") #Necessary to override FilePermissions
    }
    Process {
        ForEach ($Item in $Path) {
            Write-Verbose "FullName: $Item"
            #The ACL objects do not like being used more than once, so re-create them on the Process block
            $DirOwner = New-Object System.Security.AccessControl.DirectorySecurity
            $DirOwner.SetOwner([System.Security.Principal.NTAccount]$Account)
            $FileOwner = New-Object System.Security.AccessControl.FileSecurity
            $FileOwner.SetOwner([System.Security.Principal.NTAccount]$Account)
            $DirAdminAcl = New-Object System.Security.AccessControl.DirectorySecurity
            $FileAdminAcl = New-Object System.Security.AccessControl.DirectorySecurity
            $AdminACL = New-Object System.Security.AccessControl.FileSystemAccessRule('Builtin\Administrators','FullControl','ContainerInherit,ObjectInherit','InheritOnly','Allow')
            $FileAdminAcl.AddAccessRule($AdminACL)
            $DirAdminAcl.AddAccessRule($AdminACL)
            Try {
                $Item = Get-Item -LiteralPath $Item -Force -ErrorAction Stop
                If (-NOT $Item.PSIsContainer) {
                    If ($PSCmdlet.ShouldProcess($Item, 'Set File Owner')) {
                        Try {
                            $Item.SetAccessControl($FileOwner)
                        } Catch {
                            Write-Warning "Couldn't take ownership of $($Item.FullName)! Taking FullControl of $($Item.Directory.FullName)"
                            $Item.Directory.SetAccessControl($FileAdminAcl)
                            $Item.SetAccessControl($FileOwner)
                        }
                    }
                } Else {
                    If ($PSCmdlet.ShouldProcess($Item, 'Set Directory Owner')) {                        
                        Try {
                            $Item.SetAccessControl($DirOwner)
                        } Catch {
                            Write-Warning "Couldn't take ownership of $($Item.FullName)! Taking FullControl of $($Item.Parent.FullName)"
                            $Item.Parent.SetAccessControl($DirAdminAcl) 
                            $Item.SetAccessControl($DirOwner)
                        }
                    }
                    If ($Recurse) {
                        [void]$PSBoundParameters.Remove('Path')
                        Get-ChildItem $Item -Force | Set-Owner @PSBoundParameters
                    }
                }
            } Catch {
                Write-Warning "$($Item): $($_.Exception.Message)"
            }
        }
    }
    End {  
        #Remove priviledges that had been granted
        [void][TokenAdjuster]::RemovePrivilege("SeRestorePrivilege") 
        [void][TokenAdjuster]::RemovePrivilege("SeBackupPrivilege") 
        [void][TokenAdjuster]::RemovePrivilege("SeTakeOwnershipPrivilege")     
    }
}

function Get-UserSession {
<#  
.SYNOPSIS  
    Retrieves all user sessions from local or remote computers(s)

.DESCRIPTION
    Retrieves all user sessions from local or remote computer(s).
    
    Note:   Requires query.exe in order to run
    Note:   This works against Windows Vista and later systems provided the following registry value is in place
            HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\AllowRemoteRPC = 1
    Note:   If query.exe takes longer than 15 seconds to return, an error is thrown and the next computername is processed.  Suppress this with -erroraction silentlycontinue
    Note:   If $sessions is empty, we return a warning saying no users.  Suppress this with -warningaction silentlycontinue

.PARAMETER computername
    Name of computer(s) to run session query against
              
.parameter parseIdleTime
    Parse idle time into a timespan object

.parameter timeout
    Seconds to wait before ending query.exe process.  Helpful in situations where query.exe hangs due to the state of the remote system.
                    
.FUNCTIONALITY
    Computers

.EXAMPLE
    Get-usersession -computername "server1"

    Query all current user sessions on 'server1'

.EXAMPLE
    Get-UserSession -computername $servers -parseIdleTime | ?{$_.idletime -gt [timespan]"1:00"} | ft -AutoSize

    Query all servers in the array $servers, parse idle time, check for idle time greater than 1 hour.

.NOTES
    Thanks to Boe Prox for the ideas - http://learn-powershell.net/2010/11/01/quick-hit-find-currently-logged-on-users/

.LINK
    http://gallery.technet.microsoft.com/Get-UserSessions-Parse-b4c97837

#> 
    [cmdletbinding()]
    Param(
        [Parameter(
            Position = 0,
            ValueFromPipeline = $True)]
        [string[]]$ComputerName = "localhost",

        [switch]$ParseIdleTime,

        [validaterange(0,120)]
        [int]$Timeout = 15
    )             
    Process
    {
        ForEach($computer in $ComputerName)
        {
        
            #start query.exe using .net and cmd /c.  We do this to avoid cases where query.exe hangs

                #build temp file to store results.  Loop until we see the file
                    Try
                    {
                        $Started = Get-Date
                        $tempFile = [System.IO.Path]::GetTempFileName()
                        
                        Do{
                            start-sleep -Milliseconds 300
                            
                            if( ((Get-Date) - $Started).totalseconds -gt 10)
                            {
                                Throw "Timed out waiting for temp file '$TempFile'"
                            }
                        }
                        Until(Test-Path -Path $tempfile)
                    }
                    Catch
                    {
                        Write-Error "Error for '$Computer': $_"
                        Continue
                    }

                #Record date.  Start process to run query in cmd.  I use starttime independently of process starttime due to a few issues we ran into
                    $Started = Get-Date
                    $p = Start-Process -FilePath C:\windows\system32\cmd.exe -ArgumentList "/c query user /server:$computer > $tempfile" -WindowStyle hidden -passthru

                #we can't read in info or else it will freeze.  We cant run waitforexit until we read the standard output, or we run into issues...
                #handle timeouts on our own by watching hasexited
                    $stopprocessing = $false
                    do
                    {
                    
                        #check if process has exited
                            $hasExited = $p.HasExited
                
                        #check if there is still a record of the process
                            Try
                            {
                                $proc = Get-Process -id $p.id -ErrorAction stop
                            }
                            Catch
                            {
                                $proc = $null
                            }

                        #sleep a bit
                            start-sleep -seconds .5

                        #If we timed out and the process has not exited, kill the process
                            if( ( (Get-Date) - $Started ).totalseconds -gt $timeout -and -not $hasExited -and $proc)
                            {
                                $p.kill()
                                $stopprocessing = $true
                                Remove-Item $tempfile -force
                                Write-Error "$computer`: Query.exe took longer than $timeout seconds to execute"
                            }
                    }
                    until($hasexited -or $stopProcessing -or -not $proc)
                    
                    if($stopprocessing)
                    {
                        Continue
                    }

                    #if we are still processing, read the output!
                        try
                        {
                            $sessions = Get-Content $tempfile -ErrorAction stop
                            Remove-Item $tempfile -force
                        }
                        catch
                        {
                            Write-Error "Could not process results for '$computer' in '$tempfile': $_"
                            continue
                        }
        
            #handle no results
            if($sessions){

                1..($sessions.count - 1) | Foreach-Object {
            
                    #Start to build the custom object
                    $temp = "" | Select ComputerName, Username, SessionName, Id, State, IdleTime, LogonTime
                    $temp.ComputerName = $computer

                    #The output of query.exe is dynamic. 
                    #strings should be 82 chars by default, but could reach higher depending on idle time.
                    #we use arrays to handle the latter.

                    if($sessions[$_].length -gt 5){
                        
                        #if the length is normal, parse substrings
                        if($sessions[$_].length -le 82){
                           
                            $temp.Username = $sessions[$_].Substring(1,22).trim()
                            $temp.SessionName = $sessions[$_].Substring(23,19).trim()
                            $temp.Id = $sessions[$_].Substring(42,4).trim()
                            $temp.State = $sessions[$_].Substring(46,8).trim()
                            $temp.IdleTime = $sessions[$_].Substring(54,11).trim()
                            $logonTimeLength = $sessions[$_].length - 65
                            try{
                                $temp.LogonTime = Get-Date $sessions[$_].Substring(65,$logonTimeLength).trim() -ErrorAction stop
                            }
                            catch{
                                #Cleaning up code, investigate reason behind this.  Long way of saying $null....
                                $temp.LogonTime = $sessions[$_].Substring(65,$logonTimeLength).trim() | Out-Null
                            }

                        }
                        
                        #Otherwise, create array and parse
                        else{                                       
                            $array = $sessions[$_] -replace "\s+", " " -split " "
                            $temp.Username = $array[1]
                
                            #in some cases the array will be missing the session name.  array indices change
                            if($array.count -lt 9){
                                $temp.SessionName = ""
                                $temp.Id = $array[2]
                                $temp.State = $array[3]
                                $temp.IdleTime = $array[4]
                                try
                                {
                                    $temp.LogonTime = Get-Date $($array[5] + " " + $array[6] + " " + $array[7]) -ErrorAction stop
                                }
                                catch
                                {
                                    $temp.LogonTime = ($array[5] + " " + $array[6] + " " + $array[7]).trim()
                                }
                            }
                            else{
                                $temp.SessionName = $array[2]
                                $temp.Id = $array[3]
                                $temp.State = $array[4]
                                $temp.IdleTime = $array[5]
                                try
                                {
                                    $temp.LogonTime = Get-Date $($array[6] + " " + $array[7] + " " + $array[8]) -ErrorAction stop
                                }
                                catch
                                {
                                    $temp.LogonTime = ($array[6] + " " + $array[7] + " " + $array[8]).trim()
                                }
                            }
                        }

                        #if specified, parse idle time to timespan
                        if($parseIdleTime){
                            $string = $temp.idletime
                
                            #quick function to handle minutes or hours:minutes
                            function Convert-ShortIdle {
                                param($string)
                                if($string -match "\:"){
                                    [timespan]$string
                                }
                                else{
                                    New-TimeSpan -Minutes $string
                                }
                            }
                
                            #to the left of + is days
                            if($string -match "\+"){
                                $days = New-TimeSpan -days ($string -split "\+")[0]
                                $hourMin = Convert-ShortIdle ($string -split "\+")[1]
                                $temp.idletime = $days + $hourMin
                            }
                            #. means less than a minute
                            elseif($string -like "." -or $string -like "none"){
                                $temp.idletime = [timespan]"0:00"
                            }
                            #hours and minutes
                            else{
                                $temp.idletime = Convert-ShortIdle $string
                            }
                        }
                
                        #Output the result
                        $temp
                    }
                }
            }            
            else
            {
                Write-Warning "'$computer': No sessions found"
            }
        }
    }
}


$ErrorActionPreference='Continue'
$excludes = new-object 'System.Collections.Generic.List[string]'
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" -rec -ea SilentlyContinue | foreach {
   $CK = (Get-ItemProperty -Path $_.PsPath)
   if ($CK.ProfileImagePath -match "systemprofile" -or $CK.ProfileImagePath -match "LocalService" -or $CK.ProfileImagePath -match "NetworkService" -or $CK.ProfileImagePath -match "administrator" -or $CK.ProfileImagePath -match "администратор" -or $CK.ProfileImagePath -match "MSSQL" -or $CK.ProfileImagePath -match ".NET " -or $CK.ProfileImagePath -match "sanglyb") {
      $a = $CK
	  $excludes.add(($a.PSPath -split '\\')[7])
	}
}
$loggedOnUsers = Get-UserSession
$User = "$env:userdomain\$env:username"
$mass_length=$excludes.Count
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" -rec -ea SilentlyContinue | foreach {
   $CurrentKey = (Get-ItemProperty -Path $_.PsPath)
   $temp_uid=($CurrentKey.PSPath -split '\\')[7]
   $test=1
   for ($i=0; $i -le $mass_length-1; $i++ ) {if ($temp_uid -like $excludes[$i]) {$test=0} 
   }
   if ($test -eq 1) {
    $a = $CurrentKey
	$pat = $CurrentKey.ProfileImagePath
	$test1=1
	foreach ($loggedOnUser in $loggedOnUsers){
		if ($pat -like "*"+$loggedOnUser.Username -or $pat -match $loggedOnUser.username+"\."){
			$test1=0
		}
	}
	if ($test1 -eq 1){
	if ($pat -ne $null) {
		$pat
		Set-Owner -Path $Pat -Account $user -Recurse -ErrorAction SilentlyContinue
		cmd /c "rd /s /q $pat"
	}
	if ($a.PSPath -ne $null) {Remove-Item -Path $a.PSPath -Recurse}
	}
   }
}
