#Requires -Version 3.0
#Requires -RunAsAdministrator

<# Teodor "VR Bitman" Mazilu and contributors - 2015 and beyond
   Useful cmdlets (functions) for day-by-day IT operations on AD, Exchange, VMware, DNS and more.

   The author and contributors of this PowerShell module SHALL NOT BE LIABLE FOR ANY INCIDENTAL, SPECIAL OR CONSEQUENTIAL DAMAGES WHATSOEVER 
   (INCLUDING WITHOUT LIMITATION, DAMAGES FOR LOSS OF BUSINESS PROFIT, BUSINESS INTERRUPTION, LOSS OF BUSINESS INFORMATION, OR ANY OTHER PECUNIARY LOSS) 
   ARISING OUT OF OR RELATING TO THE USE OR INABILITY TO USE THIS SOFTWARE, EVEN IF THEY HAVE BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. #>

# Default parameters
$SCRIPT:default_domains = @{"DOM1"="DC1";"DOM2"="DC2";"DOM3"="DC3"}
$SCRIPT:default_vcenter_server = "vcenter.dom1.dom"
$SCRIPT:default_dns_zone = "dom1.dom"
$SCRIPT:default_dns_server = "10.1.2.3"
$SCRIPT:default_subnet = "10.1.2."
$SCRIPT:default_exch_transport_servers = "*hub*"
$SCRIPT:default_exch_contacts_OU = 'dom1.dom/OU1/Contacts'

function Module-Info
  {
    <# .SYNOPSIS 
       This basic command provides information on the functions contained in the module Bitman.psm1
    #>
    $info = "Module Bitman.psm1`n`nTeodor 'VR Bitman' Mazilu and contributors - 2015 and beyond`n" +
            "The author and contributors of the script code contained in this file are not responsible for any damage that may arise from the use of this code."
    Write-Warning $info
    Write-Host "`nAvailable functions:`n"
    $module_name = "Bitman"
    Get-Command -Module $module_name
  }

function Misc-ListToArray
  {
    <# .SYNOPSIS
       This is a small graphical tool which allows the user to paste a list of strings which will then be saved into a global array called $GLOBAL:global_array
       Said array can then be passed as a parameter to other functions and cmdlets of the Bitman.psm1 module.

       .EXAMPLE
       Misc-ListToArray
       VMw-TakeWSUSSnapshots $GLOBAL:global_array

    #>

    # loading .NET framework classes
    Write-Verbose "Creating the UI.."
    Write-Verbose "Loading .NET framework classes.."
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $child_form = New-Object System.Windows.Forms.Form
    $content_textbox = New-Object System.Windows.Forms.TextBox
    $InitialFormWindowState = New-Object System.Windows.Forms.FormWindowState
    $standard_form_width = 880
    $standard_form_height = 484
    [int] $standard_button_height = 23
    [int] $standard_button_width = 75
    [int] $standard_y_whitespace = [int] $standard_x_whitespace = 5
    [int] $bottom_button_baseline = $standard_form_height - $standard_button_height - $standard_y_whitespace - 5

    $child_form_onload = { 
                           $content_textbox.Text = ""
                           $content_textbox.SelectionStart = 1
                           $content_textbox.SelectionLength = 0
                           $child_form.WindowState = $InitialFormWindowState
                         }

    $child_form.BackColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
    $child_form.ClientSize = New-Object System.Drawing.Size($standard_form_width,$standard_form_height)
    $child_form.DataBindings.DefaultDataSourceUpdateMode = 0
    $child_form.FormBorderStyle = 5
    $child_form.Name = "child_form"
    $child_form.StartPosition = 4
    $child_form.Text = "Input text (one string per line):"
    $child_form.TopMost = $True
    $child_form.add_Load($child_form_onload)

    $content_textbox.DataBindings.DefaultDataSourceUpdateMode = 0
    $content_textbox.Location = New-Object System.Drawing.Point(12,11)
    $content_textbox.Multiline = $True
    $content_textbox.Name = "content_textbox"
    $content_textbox.Size = New-Object System.Drawing.Size(($standard_form_width - 22),($standard_form_height - 54))
    $content_textbox.TabIndex = 0
    $content_textbox.ReadOnly = $false
    $content_textbox.ScrollBars = "Vertical"
    $content_textbox.Font = New-Object System.Drawing.Font("Lucida Console",8.25,0,3,0)
    $child_form.Controls.Add($content_textbox)

    # creating the OK button
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Size(($standard_form_width/2 - $standard_button_width - $standard_x_whitespace), $bottom_button_baseline)
    $OKButton.Size = New-Object System.Drawing.Size($standard_button_width, $standard_button_height)
    $OKButton.Font = $standard_font
    $OKButton.Text = "OK"
    $OKButton.Add_Click({ $GLOBAL:global_array = $content_textbox.Lines; UI-MessageBox "Created $$GLOBAL:global_array with $(($GLOBAL:global_array | Measure).Count) elements."; $child_form.Close() })
    $child_form.Controls.Add($OKButton)
        
    # creating the Cancel button
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Size(($standard_form_width/2 + $standard_x_whitespace), $bottom_button_baseline)
    $CancelButton.Size = New-Object System.Drawing.Size($standard_button_width, $standard_button_height)
    $CancelButton.Font = $standard_font
    $CancelButton.Text = "Cancel.."
    $CancelButton.Add_Click({$child_form.Close()})
    $child_form.Controls.Add($CancelButton)

    $InitialFormWindowState = $child_form.WindowState 
    $child_form.ShowDialog()| Out-Null
  }

function Misc-StringToCode # handle with care :)
  {
    param([parameter(Mandatory=$true)] [string]$String)
    $chars = $String.trim() -split ""
    $chars | % { if ($_) { [string]$output += [int][char]$_ - 32 } }  
    New-Object PSObject -Property @{Length = ($String.Length - 1); Values = $output; Code = "([string](0..$($String.Length-1)|%{[char][int](32+(`"$output`").substring((`$_*2),2))})).replace(' ','')"} | FL
  }

### DNS functions ###

function DNS-AddRecord
  { 
    <# .SYNOPSIS
       This command adds a DNS A record in the default DNS zone as specified in Bitman.psm1 (different zones may be specified through the parameters)
       The function also creates the corresponding reverse record!

       .EXAMPLE
       DNS-AddRecord Test 1.2.3.4
    #>
    
    param([parameter(Mandatory=$true)] [string]$name, [parameter(Mandatory=$true)] [string]$IP, [string]$zone=$SCRIPT:default_dns_zone)
    
    # adding the record in the forward zone
    dnscmd $SCRIPT:default_dns_server /recordadd $zone $name A $IP
    
    # adding the record in the reverse zone
    $octets = $IP.Split('.')
    $PTR = "$($octets[2]).$($octets[1]).$($octets[0]).in-addr.arpa"
    $FQDN = "$($name).$($zone)"
    dnscmd $SCRIPT:default_dns_server /recordadd $PTR $octets[3] PTR $FQDN
  }
  
function DNS-DeleteRecord
  {
    <# .SYNOPSIS
       Deletes DNS records in the default DNS zone as specified in Bitman.psm1 (the user can specify a different zone at the command line); the script also deletes the reverse record!

       .EXAMPLE
       DNS-DeleteRecord Test 1.2.3.4
    #>

    [cmdletbinding()] param([parameter(Mandatory=$true)] [string]$name, [parameter(Mandatory=$true)] [string]$IP, [string]$zone=$SCRIPT:default_dns_zone)
    
    dnscmd $SCRIPT:default_dns_server /recorddelete $zone $name A $IP /f
    if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -or $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
      {
        Write-Verbose "Reverse record should have disappeared as well, running nslookup for the IP."
        nslookup $IP
      }
  }

### Network functions ###

function Net-FindReachableIPs
  {
    <# .SYNOPSIS
       Scans a given subnet and returns the list IP addresses which respond to ping; it is important to note that an unresponsive IP might not necessarily 
       mean that the corresponding machine is down, it might just be that it is unreachable at a network level or that ICMP is disabled.
       The default subnet is the one specied in Bitman.psm1 with the var name $SCRIPT:default_subnet, but a different subnet can always be specified at the command line.

       .EXAMPLE
       Net-FindReachableIPs 192.168.1.

       .EXAMPLE
       Net-FindReachableIPs 172.16.30. 200 210
    #>

    [cmdletbinding()] param([string]$subnet = $SCRIPT:default_subnet, [int]$start = 1, [int]$end = 254)
    Write-Verbose "Pinging $subnet from $start to $end." 
    
    # the -count parameter is needed so that each computer is only pinged once, generating only one result
    # otherwise, by default, each computer will generate 4 results!
    $start..$end | ? { Test-Connection "$subnet$_" -Count 1 -Quiet } | % { "$subnet$_" }
  }

function Net-TestTCPPort
  {
    <# .SYNOPSIS
       Tests whether a given TCP port is open (reachable) on a remote server

       .EXAMPLE
       Net-TestTCPPort -ComputerName 10.1.10.240 -Port 3389 -Protocol TCP -Verbose
    #>

    [cmdletbinding()] Param(
                             [parameter(ParameterSetName='ComputerName', Position=0)] [string] $ComputerName,
                             [parameter(ParameterSetName='IP', Position=0)] [System.Net.IPAddress] $IPAddress,
                             [parameter(Mandatory=$true , Position=1)] [int] $Port,
                             [parameter(Mandatory=$true, Position=2)] [ValidateSet("TCP", "UDP")] [string] $Protocol
                           )

    $result = $false
    $RemoteServer = If ([string]::IsNullOrEmpty($ComputerName)) {$IPAddress} Else {$ComputerName}
    If ($Protocol -eq 'TCP')
      {
        $test = New-Object System.Net.Sockets.TcpClient;
        Try
          {
            Write-Verbose "Connecting to $RemoteServer : $Port (TCP)..";
            $test.Connect($RemoteServer, $Port);
            Write-Verbose "Connection to $RemoteServer successful";
            $result = $true;
          }
        Catch
          {
            Write-Verbose "Connection to $RemoteServer failed";
          }
        Finally
          {
            $test.Close();
          }
      }
    return $result
  }

function Net-FindHostnamesByIPs
  {
    <# .SYNOPSIS
       Takes an array of IPs and for each IP tries to find the corresponding VM or at least return the DNS record(s) and whether ports 3389 or 22 are open.
       For VM checks, it connects to the default vCenter Server as defined in Bitman.psm1

       .EXAMPLE
       Net-FindHostnamesByIPs 10.1.10.240,10.1.10.241,10.1.10.242
    #>

    [cmdletbinding()] Param([parameter(Mandatory=$true)] [array]$array)

    if ($array)
      {
        Write-Host "Starting analysis with $($array.count) IPs`n`n"

        VMw-ConnectToDefaultVC
        $VMs = Get-View -ViewType VirtualMachine

        ForEach ($IP in $array)
          {
            Write-Host "IP: $IP"
            nslookup $IP.Trim()
            foreach ($VM in $VMs) { if ($VM.Guest.IPAddress -eq ($IP.Trim())) { Write-Host "VMware: $($VM.Name)" }  }
            $RDPtest = Net-TestTCPPort -ComputerName $IP -Port 3389 -Protocol TCP -Verbose
            $SSHtest = Net-TestTCPPort -ComputerName $IP -Port 22 -Protocol TCP -Verbose
            if ($RDPtest) { Write-Host "RDP OPEN" }
            if ($SSHtest) { Write-Host "SSH OPEN" }
            Write-Host "`n`n"
          }
      }
  }

### Active Directory functions ###

function AD-GetObjects
  {
    <# .SYNOPSIS
       Performs a "contains" search in the current Active Directory domain, returning any object that matches the specified input string;
       By default the search looks at the name property, but it can be overriden with the -key parameter.
       A switch (-SimpleView) can be used to produce a simple, human readable output containing only the Name and Description columns.
       Otherwise it returns all the objects and displays all their properties.
       If necessary, specific properties can be specified to include in the output.

       .EXAMPLE
       AD-GetObjects JohnCandy
    #>

    [cmdletbinding()] param([parameter(Mandatory=$true)] [string]$string, [string]$key = "name", [string]$prop = "*", [switch]$SimpleView)

    $curdomain = (Get-ADDomain -Current LocalComputer | Select DNSRoot).DNSRoot
    Write-Host "Performing 'contains' search in domain $curdomain"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $objects = @()
    
    if ($SimpleView)
      {
        $objects = Get-ADObject -Filter "$key -like '*$string*'" -Properties * | Select Name, Description
      }
    else
      {
        $objects = Get-ADObject -Filter "$key -like '*$string*'" -Properties $prop
      }
    $sw.Stop()
    Write-Host "I found $($objects.count) objects in: $([Math]::Round($sw.Elapsed.Milliseconds)) milliseconds."
    $objects
  } 

function AD-FindGroups
  {
    <# .SYNOPSIS
       Performs a "contains" group search in the current Active Directory domain, returning any group whose name matches the specified input string;
       A switch (-SimpleView) can be used to produce a simple, human readable output containing only the Name and Description columns.
       Otherwise it returns all the objects and displays all their properties.

       .EXAMPLE
       AD-GetGroups TestGroup1 -SimpleView

       .EXAMPLE
       $vc_groups = AD-GetGroups TestGroup1
    #>

    [cmdletbinding()] param([parameter(Mandatory=$true)] [string]$SearchInGroups, [switch]$SimpleView)

    if ($SimpleView)
      {
        Write-Verbose "SimpleView on; displaying only names and descriptions.`n"
        Get-ADGroup -Filter "Name -like '*$SearchInGroups*'" -Properties * | Select Name, Description
      }
    else
      {
        Write-Verbose "SimpleView off; returning all properties.`n"
        Get-ADGroup -Filter "Name -like '*$SearchInGroups*'" -Properties *
      }
  }

function AD-FindGroupsWithMembers
  {
    <# .SYNOPSIS
       Performs a "contains" group search in the current Active Directory domain, finding any group whose name matches the specified input string and listing their members

       .EXAMPLE
       AD-FindGroupsWithMembers TestGroup1
    #>

	[cmdletbinding()] param([parameter(Mandatory=$true)] [string]$SearchInGroups)
    
    $groups = @()
    $groups = Get-ADGroup -Filter "Name -like '*$SearchInGroups*'"
    Write-Host "Found: $($groups.count) results."
	if ($groups.count -gt 0)
      {
        ForEach ($group in $groups) 
          {
            Write-Host "`nGroup: $($group.Name)`n"
            Get-ADGroupMember $group | Select @{Label="User";E={$_.Name}},SamAccountName | FT -AutoSize
          }
      }
  }

function AD-SetUserPassword
  {
    <# .SYNOPSIS
       This function (re)sets the password of a domain account across all domains of an organization (defined in Bitman.psm1).
       If a domain is explicitly specified via the Domain parameter, the function will work only with that one.

       .EXAMPLE
       AD-SetPassword-MB TestUser

       .EXAMPLE
       AD-SetPassword-MB TestUser -Domain MyDom
    #>

    [cmdletbinding()] param([string]$Domain)
    
    $Cred = Get-Credential
    
    # if the user doesn't specify a domain, I cycle through all domains and reset the password for each; else I work with one domain
    if (!$Domain)
      {
        foreach ($Key in $SCRIPT:default_domains.GetEnumerator())
          {
            Write-Verbose "Setting password for domain $($Key.Name) on domain controller $($Key.Value).."
            Set-ADAccountPassword -Server $Key.Value -Identity ($Cred.Username -replace "\\", "") -NewPassword $Cred.Password
          }
        
        # I delete all Kerberos tickets to have a clean situation
        Write-Verbose "Purging Kerberos tickets.."
        (klist purge) | Out-Null
        Write-Verbose "Done."
      }
    else
      {
        Write-Verbose "Setting password on domain controller $($SCRIPT:default_domains.$Domain)"
        Set-ADAccountPassword -Server $SCRIPT:default_domains.$Domain -Identity ($Cred.Username -replace "\\", "") -NewPassword $Cred.Password
      }
  }

function AD-FindHungSessions
  {
    <# .SYNOPSIS
       This function searches for "hung" sessions for a given user account on Windows machines in the current Active Directory domain and returns all sessions found.
       The function interrogates all servers with a computer account in Active Directory (current domain).
       Because the output can be long at times, the function defaults to creating a file C:\hungsessions.txt.
       The function automatically opens the file with Notepad at the end of execution

       .EXAMPLE
       AD-FindHungSessions TestUser
    #>

    [cmdletbinding()] param([parameter(Mandatory=$true)] [string]$account)

    $curdomain = (Get-ADDomain -Current LocalComputer | Select DNSRoot).DNSRoot
    Write-Host "Working with computer accounts in domain $curdomain"
    
    # the output could be lengthy, so I create a log file and open it with Notepad as soon as execution finishes
    $outputfile = "C:\hungsessions.txt"
    Write-Verbose "Creating output file $($outputfile)"
    New-Item $outputfile -type file -force
    
    # I retrieve an array of all servers in the domain with an LDAP query; unfortunately I can't filter out inconsistencies
    Write-Verbose "`nRetrieving server list.."
    $servers = @()
    $servers = Get-ADComputer -LDAPFilter "(&(objectcategory=computer)(OperatingSystem=*server*))"

    # if I have a valid list of 1 or more servers I interrogate each to see if there are sessions for the specified user
    if ($servers.count -gt 0)
      {
        Write-Verbose "Retrieved a list of $($servers.count) servers!"
        Write-Host "Searching..`n"
        foreach ($server in $servers)
          {
            $result = (qwinsta /server:$($server.name) | findstr -i $($account))
            if ($result -match "Active|Disc") 
              {
                $out = $server.name + $result; Write-Host $out; $out | Out-File $outputfile -Append
              }
          }
        Write-Verbose "Finished my search, opening Notepad with the results file."
        notepad $outputfile
      }
    else
      {
        Write-Warning "Something went wrong, Active Directory gave me 0 computer names!"
      }
  }

function AD-LocalUsersAndGroups
  {
    <# .SYNOPSIS
       This function interrogates a list of hostnames and retrieves local users and groups; input can come either from an array of hostnames or from a file.
       Input file is C:\Hostnames.txt, which must be created manually prior to function execution.
       Output is always a file, C:\entities.txt

       .EXAMPLE
       $computers = "server1", "server2"
       AD-LocalUsersAndGroups $computers

       .EXAMPLE
       AD-LocalUsersAndGroups -FromFile
    #>

    [cmdletbinding()] param($Computers, [switch]$GridView, [switch]$FromFile)
    
    function VRB-LocalUSers($computer)
      {
        $list = @()
        Write-Verbose "Checking $computer.."
        $computerName = $computer
        if ([ADSI]::Exists("WinNT://$computerName,computer")) 
          { 
            $computer = [ADSI]"WinNT://$computerName,computer" 
            $computer.psbase.Children | Where-Object { $_.psbase.schemaclassname -eq 'group' } | % {        
                $LocalGroupName = $_.Name
                $group = [ADSI]("WinNT://$computerName/$($LocalGroupName),group") 
                $members = @() 
                $Group.Members() | % { 
                    $AdsPath = $_.GetType().InvokeMember("Adspath", 'GetProperty', $null, $_, $null) 
                    # Domain members will have an ADSPath like WinNT://DomainName/UserName
                    # Local accounts will have a value like WinNT://DomainName/ComputerName/UserName
                    $a = $AdsPath.split('/',[StringSplitOptions]::RemoveEmptyEntries) 
                    $name = $a[-1] 
                    $domain = $a[-2] 
                    $class = $_.GetType().InvokeMember("Class", 'GetProperty', $null, $_, $null) 
                    $member = New-Object PSObject 
                    $member | Add-Member -MemberType NoteProperty -Name "Computer" -Value $computerName
                    $member | Add-Member -MemberType NoteProperty -Name "Group" -Value $LocalGroupName.toString()
                    $member | Add-Member -MemberType NoteProperty -Name "Name" -Value $name 
                    $member | Add-Member -MemberType NoteProperty -Name "Domain" -Value $domain 
                    $member | Add-Member -MemberType NoteProperty -Name "Class" -Value $class 
                    $members += $member 
                  } 
                if ($members.count -ne 0) { $list += $members } 
            }
          }  
        return $list | Select Group, Domain, Name, Class | Sort Group
      }

    $inputfile = "C:\Hostnames.txt"
    $outputfile = "C:\entities.txt"
    Write-Verbose "Creating output file $($outputfile)"
    New-Item $outputfile -type file -force   

    if ($FromFile) 
      { 
        $array = Get-Content $inputfile
        Write-Verbose "Working with $($array.count) hostnames loaded from $($inputfile)."
      } 
    else 
      {
        $array = $computers
        Write-Verbose "Working with $($array.count) hostnames loaded from command line parameters."
      }
    
    if ($($array.count) -eq 0)
      {
        Write-Warning "I have 0 hostnames, quitting."
        Exit
      }
    
    ForEach ($hostname in $array)
      {
        $list = VRB-LocalUsers $_
        if ($list)
          {
            $original_group = $list[0].group
            $real_list = $original_group + ": "
            foreach ($item in $list)
              {
                $curr_group = $item.group
                if ($curr_group -eq $original_group)
                  {
                    $real_list += ($item.Name)
                    if ($list[$list.IndexOf($item)+1].group -eq $curr_group)
                      {
                        $real_list += ", "
                      }
                  }
                else
                  {
                    $real_list += ("; " + $curr_group + ": " + $item.Name)
                    if ($list[$list.IndexOf($item)+1].group -eq $curr_group)
                      {
                        $real_list += ", "
                      }
                    $original_group = $curr_group
                  }
              }
              $real_list | Out-File $outputfile -Append  
          }
        else
          {
            "N/A" | Out-File $outputfile -Append   
          }
      }
  }

function AD-ShowLogonScript
  {
    <# .SYNOPSIS
       This function interrogates the current Active Directory domain controllers and displays the script path of a given user account, while also listing the contents of the script.

       .EXAMPLE
       AD-ShowLogonScript TestUser
    #>

    [cmdletbinding()] param([parameter(Mandatory=$true)] $account)

    $curdomain = Get-ADDomain -Current LocalComputer
    $curdomain_name = ($curdomain | Select Name).Name
    $curdomain_completename = ($curdomain | Select DNSRoot).DNSRoot
    Write-Host "Working with domain $curdomain_completename"
    Write-Verbose "Searching AD.."
    $user = Get-ADUser $account -Properties ScriptPath

    if ($user)
      {
        Write-Verbose "User found, retrieving script path.."
        $full_path = ""
        $base_path = "\\$curdomain_name\netlogon\"
        $script_path = $user | Select -ExpandProperty ScriptPath
        if ($script_path) 
          { 
            $full_path = $base_path + $script_path
            Write-Host "`n$full_path`n`n== SCRIPT CONTENTS ==`n"
            Get-Content $full_path
            Write-Host "`n"
          }
      }
  }

function AD-CompareUsers
  {
    <# .SYNOPSIS
       A simplistic GUI that allows an administrator to compare and "copy" groups from the membership of one user to another.
       It can also clone logon scripts and Exchange public folder permissions (it connects automatically to the Exchange cluster of the current domain).
       Developed and tested against domains of Windows 2003 functional level and Exchange 2007.

       .EXAMPLE
       AD-CompareUsers TestUser1 TestUser2
    #>
    
    [cmdletbinding()] param([parameter(Mandatory=$true)] [string]$from, [parameter(Mandatory=$true)] [string]$to)

    # this function will return the logon script of a domain account
    function AD-LogonScript([parameter(Mandatory=$true)] $Account)
      {
        Write-Verbose "Retrieving script path for $account.."
        $curdomain = Get-ADDomain -Current LocalComputer
        $curdomain_name = ($curdomain | Select Name).Name
        $curdomain_completename = ($curdomain | Select DNSRoot).DNSRoot
        $full_path = ""
        $base_path = "\\$curdomain_name\netlogon\"
        $script_path = Get-ADUser $account -Properties ScriptPath | Select -ExpandProperty ScriptPath
        if ($script_path) { $full_path = $base_path + $script_path }
        return $full_path
      }

    function Clone_Logon_Scripts
      {
        $from_script = AD-LogonScript $from
        if ($from_script -ne "") 
          { 
            Write-Verbose "Trying to copy source script contents and create a new with the correct name.."
            $base_path = Split-Path -parent $from_script
            $script_name = "\" + $to + ".bat"
            $destination = $base_path + $script_name
            Copy-Item -Path $from_script -Destination $destination -Force -Confirm:$False
            Set-ADUser $to –scriptPath ((Get-ADUser $from -Properties ScriptPath | Select -ExpandProperty ScriptPath).Split("\")[0] + $script_name)
            UI-MessageBox "Done! Close this program and rerun it to check!"
          } 
        else 
          { 
            UI-MessageBox "Nothing to copy!"
          }
      }

    $SCRIPT:PublicFolders = $null

    function Retrieve_PF_Permissions
      {          
        # Source text box
        $objTextBox5.Text = "Working.."
        
        # Destination text box
        $objTextBox6.Text = "Working.."
            
        # retrieving permissions
        Write-Verbose "Retrieving public folders list.."
        $SCRIPT:PublicFolders = Get-PublicFolder -Recurse
    
        # I iterate through all the public folders and find the folders for which the source & dest users have permissions
        Write-Verbose "Getting user CN for $from"
        Write-Verbose "Getting user CN for $to"
        $user = Get-ADUser $from -Properties CanonicalName | Select -ExpandProperty CanonicalName
        $user_to = Get-ADUser $to -Properties CanonicalName | Select -ExpandProperty CanonicalName
        if ($user)
          {
            $SCRIPT:final_permissions = @()  
            $final_permissions2 = @()          
            Write-Verbose "Sifting through the public folders looking for users $($user.split("/")[-1]) and $($user_to.split("/")[-1])"
            Foreach ($f in $SCRIPT:PublicFolders)
              {
                Write-Verbose "Analyzing folder: $($f.name)"
                $p = Get-PublicFolderClientPermission -Identity $f.EntryId | ? { $_.User -match $user } 
                if ($p) 
                  { 
                    Write-Verbose "Source user has permissions, memorizing them."
                    $SCRIPT:final_permissions += $p 
                  }
                $p = Get-PublicFolderClientPermission -Identity $f.EntryId | ? { $_.User -match $user_to } 
                if ($p) 
                  { 
                    Write-Verbose "Destination user has permissions, memorizing them."
                    $final_permissions2 += $p 
                  }
              }
            $objTextBox5.Text = ($SCRIPT:final_permissions | Select Identity, AccessRights | FL | Out-String)
            $objTextBox6.Text = ($final_permissions2 | Select Identity, AccessRights | FL | Out-String)
            Write-Verbose "Found $($SCRIPT:final_permissions.count) permissions for user $($user.split("/")[-1])."
            Write-Verbose "Found $($final_permissions2.count) permissions for user $($user_to.split("/")[-1])."
          }
        $cloneCalendarsButton.Enabled = $true
        $sonProgressBar.Style = 1 # "stops" the marquee progress bar by changing its style to blocks (normal)
      }

    function Clone_PF_Permissions
      {
        if ($SCRIPT:PublicFolders -and ($SCRIPT:final_permissions.count -gt 0))
          {
            Write-Verbose "Cloning $($SCRIPT:final_permissions.count) permissions."
            Write-Verbose "Getting user CN for $to"
            $user = (Get-ADUser $to | Select UserPrincipalName).UserPrincipalName
            Foreach ($p in $SCRIPT:final_permissions)
              {
                Add-PublicFolderClientPermission -Identity $p.Identity -User $user -AccessRights $p.AccessRights
                Write-Verbose "Added permission $($p.Identity) $($p.AccessRights)"
              }
          }
        else
          {
            Write-Verbose "I have nothing to work with. Either the source user has zero permissions or there are no public folders."
            UI-MessageBox "I have nothing to work with!"
          }
        $getCalendarPermissionsButton.Enabled = $true;
      }

    function OpenSelectedText
      {
        $selection = ""
        if ($objTextBox.SelectedText) { $selection = $objTextBox.SelectedText; }
        if ($objTextBox2.SelectedText) { $selection = $objTextBox2.SelectedText; }
        if ($selection) 
          {
            Write-Verbose "Starting Windows Explorer.."
            & 'explorer.exe' @($selection)
          } 
        else
          {
            Write-Verbose "Could not detect any selected text."
            UI-MessageBox "Select something! Preferably a valid path!"
          }
      }

    function CopyGroups
      {
        $items = $objListbox.SelectedItems
        
        # proceeding to "copy" groups from one user to another
        Write-Verbose "User selected $($objListbox.SelectedItems.count) values."
        if ($items.Count -gt 0) 
          { 
            $mainProgressBar.Value = 0
            $mainProgressBar.Step = ($mainProgressBar.Maximum / $items.Count)
            ForEach ($item in $items)
              { 
                 Write-Verbose "Adding target to groups.."
                 Write-Verbose "Cleaning string $item with target length $SCRIPT:max_name_length1"
                 $group = CleanString -str $item -target ($SCRIPT:max_name_length1)
                 Write-Verbose "Adding user to $($group).."
                 Add-ADGroupMember $group $to

                 $SCRIPT:listSelItems += $item; 
                 $mainProgressBar.PerformStep()
              }
            $mainProgressBar.Value = $mainProgressBar.Maximum
            UI-MessageBox "Done (hopefully without errors). Close this program and run it again to check."
            $wait_for_update_label.Visible = $true
            GetUserData
            UpdateUI
            $wait_for_update_label.Visible = $false
          }
        else
          {
            UI-MessageBox "Select at least one group please."
          }
      }

    function UpdateUI
      {
        Write-Verbose "Updating the UI.."
        
        # updating the first list box (source groups)
        $objListBox.Items.Clear()
        $SCRIPT:new_from_values | % { [void] $objListBox.Items.Add($_) }
        
        # updating the second list box (destination groups)
        $objListBox2.Items.Clear()
        $SCRIPT:new_to_values | % { [void] $objListBox2.Items.Add($_) }
        
        # updating the third list box (source OUs)
        $OUs_ListBox1.Items.Clear()
        $OUs_from | % { [void] $OUs_ListBox1.Items.Add($_) }

        # updating the fourth list box (destination OUs)
        $OUs_ListBox2.Items.Clear()
        $OUs_to | % { [void] $OUs_ListBox2.Items.Add($_) }
        
        # updating the fifth list box (source group types)
        $objListBox5.Items.Clear()
        $types_from | % { [void] $objListBox5.Items.Add($_.ToString()[0]) }

        # updating the sixth list box (destination group types)
        $objListBox6.Items.Clear()
        $types_to | % { [void] $objListBox6.Items.Add($_.ToString()[0]) }

        $mainProgressBar.Value = 0
        $objLabel.ForeColor = [System.Drawing.Color]::FromArgb(255,0,0,0)
        $objLabel2.ForeColor = [System.Drawing.Color]::FromArgb(255,0,0,0)
      }

    function GroupsDiff
      {
        if ($DiffButton.Text -eq "Diff")
          {
            Write-Verbose "Calculating differences..."
            $clean_from_values = @()
            $SCRIPT:new_from_values | % { $clean_from_values += ($_ -split '>')[0].Trim() }
            Write-Verbose "Cleaned from values:"
            $clean_from_values | % { Write-Verbose $_ }
            $clean_to_values = @()
            $SCRIPT:new_to_values | % { $clean_to_values += ($_ -split '>')[0].Trim() }
            Write-Verbose "Cleaned to values:"
            $clean_to_values | % { Write-Verbose $_ }
    
            $objListBox.Items.Clear()
            $objListBox2.Items.Clear()
            $OUs_ListBox1.Items.Clear()
            $OUs_ListBox2.Items.Clear()
            $objListBox5.Items.Clear()
            $objListBox6.Items.Clear()
    
            $i = 0
            $clean_from_values | % { 
                                     if ($clean_to_values -notcontains $_) 
                                       { 
                                         $objListBox.Items.Add($SCRIPT:new_from_values[$i])
                                         $OUs_ListBox1.Items.Add($OUs_from[$i])
                                         $objListBox5.Items.Add($types_from[$i].ToString()[0])
                                       } 
                                     $i++
                                   }
            $DiffButton.Text = "Full"

            $objLabel.ForeColor = [System.Drawing.Color]::FromArgb(255,255,0,0)
            $objLabel2.ForeColor = [System.Drawing.Color]::FromArgb(255,255,0,0)
          }
        else
          {
            Write-Verbose "Restoring groups..."
            UpdateUI
            $DiffButton.Text = "Diff"
          }
      }

    function DoubleSelectionBox([switch]$LogonScripts, [switch]$Calendars)
      {
        $SCRIPT:listSelItems = @()
        Write-Verbose "Data collected, about to create the UI; data:"
        Write-Verbose "$from $to $($items1.Count) $description1 $($items2.Count) $description2 $LogonScripts $Calendars"
    
        # loading .NET framework classes
        Write-Verbose "Creating the UI.."
        Write-Verbose "Loading .NET framework classes.."
        [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
        [System.Windows.Forms.Application]::EnableVisualStyles()
    
        # setting a few "standard" parameters
        [int] $standard_form_height = 600
        [int] $standard_form_width = 1195
        [int] $child_form_height = $standard_form_height - 50
        [int] $child_form_width = $standard_form_width - 50
        [int] $standard_button_height = 23
        [int] $standard_button_width = 75
        [int] $standard_label_height = 20
        [int] $standard_label_width = [int] $standard_listbox_width = 815
        [int] $standard_child_label_width = [int] $standard_child_listbox_width = $child_form_width - ($standard_x_whitespace * 2) - 30
        [int] $standard_listbox_height = 235
        [int] $standard_y_whitespace = [int] $standard_x_whitespace = 5
        [int] $bottom_button_baseline = $standard_form_height - $standard_button_height - $standard_y_whitespace - 40
        [int] $bottom_child_button_baseline = $child_form_height - $standard_button_height - $standard_y_whitespace - 40
        [int] $top_label_baseline =  $standard_y_whitespace
        $standard_font = New-Object System.Drawing.Font("Gill Sans MT",9.75,1,3,0)

        # creating the main form
        Write-Verbose "Creating the main form.."
        $SCRIPT:objForm = New-Object System.Windows.Forms.Form 
        $SCRIPT:objForm.Size = New-Object System.Drawing.Size($standard_form_width, $standard_form_height)
        $SCRIPT:objForm.StartPosition = "CenterScreen"
        $SCRIPT:objForm.FormBorderStyle = 'Fixed3D'
        $SCRIPT:objForm.MaximizeBox = $false
        $SCRIPT:objForm.KeyPreview = $True
        $SCRIPT:objForm.Add_KeyDown({if ($_.KeyCode -eq "Enter") {CopyGroups}})
        $SCRIPT:objForm.Add_KeyDown({if ($_.KeyCode -eq "Escape") {$SCRIPT:objForm.Close()}})
        
        # setting variable parameters for the form
        $SCRIPT:objForm.Text = "Make a selection and click COPY!"

        Write-Verbose "Creating buttons, list boxes and labels in the main form.."
        
        # creating the OK button
        $OKButton = New-Object System.Windows.Forms.Button
        $OKButton.Location = New-Object System.Drawing.Size(($standard_form_width/2 - $standard_button_width - $standard_x_whitespace), $bottom_button_baseline)
        $OKButton.Size = New-Object System.Drawing.Size($standard_button_width, $standard_button_height)
        $OKButton.Font = $standard_font
        $OKButton.Text = "COPY!"
        $OKButton.Add_Click({ CopyGroups })
        $SCRIPT:objForm.Controls.Add($OKButton)
        
        # creating the Cancel button
        $CancelButton = New-Object System.Windows.Forms.Button
        $CancelButton.Location = New-Object System.Drawing.Size(($standard_form_width/2 + $standard_x_whitespace), $bottom_button_baseline)
        $CancelButton.Size = New-Object System.Drawing.Size($standard_button_width, $standard_button_height)
        $CancelButton.Font = $standard_font
        $CancelButton.Text = "Cancel.."
        $CancelButton.Add_Click({$SCRIPT:objForm.Close()})
        $SCRIPT:objForm.Controls.Add($CancelButton)

        # creating the Diff button
        $DiffButton = New-Object System.Windows.Forms.Button
        $DiffButton.Location = New-Object System.Drawing.Point(($standard_form_width * 0.8), $bottom_button_baseline)
        $DiffButton.Size = New-Object System.Drawing.Size($standard_button_width, $standard_button_height)
        $DiffButton.Font = $standard_font
        $DiffButton.Text = "Diff"
        $DiffButton.Add_Click({ GroupsDiff })
        $SCRIPT:objForm.Controls.Add($DiffButton)

        # creating the first label for the first list and adding it to the form (source groups)
        $objLabel = New-Object System.Windows.Forms.Label
        $objLabel.Location = New-Object System.Drawing.Size($standard_x_whitespace, $top_label_baseline) 
        $objLabel.Size = New-Object System.Drawing.Size($standard_label_width, $standard_label_height)
        $objLabel.Font = $standard_font
        $objLabel.Text = $description1
        $SCRIPT:objForm.Controls.Add($objLabel) 
        
        # creating the first list box and adding it to the form (source groups)
        $objListBox = New-Object System.Windows.Forms.ListBox 
        $objListBox.Location = New-Object System.Drawing.Size($standard_x_whitespace, ($objLabel.location.Y + $objLabel.Size.Height + $standard_y_whitespace)) 
        $objListBox.Size = New-Object System.Drawing.Size($standard_listbox_width, $standard_listbox_height) 
        $objListBox.Font = "Lucida Console,7"
        $objListbox.SelectionMode = "MultiExtended"
        $SCRIPT:new_from_values | % { [void] $objListBox.Items.Add($_) }
        $SCRIPT:objForm.Controls.Add($objListBox) 
        $objListbox.Add_Click({ $OUs_ListBox1.ClearSelected(); $objListBox5.ClearSelected(); 
                                $objListBox.SelectedIndices | % { $OUs_ListBox1.SelectedIndex = $objListBox5.SelectedIndex = $objListbox.SelectedIndex = $_ } })
    
        # creating the second label for the second list
        $objLabel2 = New-Object System.Windows.Forms.Label
        $objLabel2.Location = New-Object System.Drawing.Size($standard_x_whitespace, ($objListBox.location.Y + $objListBox.Size.Height + $standard_y_whitespace)) 
        $objLabel2.Size = New-Object System.Drawing.Size($standard_label_width, $standard_label_height)
        $objLabel2.Font = $standard_font
        $objLabel2.Text = $description2
        $SCRIPT:objForm.Controls.Add($objLabel2) 
        
        # creating the second list box and adding it to the form
        $objListBox2 = New-Object System.Windows.Forms.ListBox 
        $objListBox2.Location = New-Object System.Drawing.Size($standard_x_whitespace, ($objLabel2.location.Y + $objLabel2.Size.Height + $standard_y_whitespace)) 
        $objListBox2.Size = New-Object System.Drawing.Size($standard_listbox_width, $standard_listbox_height) 
        $objListBox2.Font = "Lucida Console,7"
        $objListbox2.SelectionMode = "MultiExtended"
        $SCRIPT:new_to_values | % { [void] $objListBox2.Items.Add($_) }
        $SCRIPT:objForm.Controls.Add($objListBox2)
        $objListbox2.Add_Click({ 
                                 $OUs_ListBox2.ClearSelected(); $objListBox6.ClearSelected(); 
                                 Write-verbose "Selected cleared in OUs_ListBox2 and objListBox6"
                                 Write-Verbose "Selected count: $($objListBox2.SelectedIndices.count)"
                                 $objListBox2.SelectedIndices | % { Write-verbose "selecting index: $_"; $OUs_ListBox2.SelectedIndex = $objListBox6.SelectedIndex = $objListbox2.SelectedIndex = $_ }
                               })

        # creating the third label for the third list (source OUs)
        $OUs_label1 = New-Object System.Windows.Forms.Label
        $OUs_label1.Location = New-Object System.Drawing.Size(($objLabel.Location.X + $objLabel.Size.Width + $standard_x_whitespace), $standard_y_whitespace)
        $OUs_label1.Size = New-Object System.Drawing.Size(($standard_listbox_width/2.8), $standard_label_height)
        $OUs_label1.Font = $standard_font
        $OUs_label1.Text = "Path:"
        $SCRIPT:objForm.Controls.Add($OUs_label1)
        
        # creating the third list box and adding it to the form (source OUs)
        $OUs_ListBox1 = New-Object System.Windows.Forms.ListBox 
        $OUs_ListBox1.Location = New-Object System.Drawing.Size($OUs_label1.Location.X, ($OUs_label1.location.Y + $OUs_label1.Size.Height + $standard_y_whitespace))
        $OUs_ListBox1.Size = New-Object System.Drawing.Size(($standard_listbox_width/2.8), $standard_listbox_height) 
        $OUs_ListBox1.Font = "Lucida Console,7"
        $OUs_ListBox1.SelectionMode = "MultiExtended"
        $OUs_Listbox1.Enabled = $false
        $OUs_from | % { [void] $OUs_ListBox1.Items.Add($_) }
        $SCRIPT:objForm.Controls.Add($OUs_ListBox1)

        # creating the fourth label for the fourth list (destination OUs)
        $OUs_label2 = New-Object System.Windows.Forms.Label
        $OUs_label2.Location = New-Object System.Drawing.Size($OUs_label1.Location.X, ($OUs_ListBox1.location.Y + $OUs_ListBox1.Size.Height + $standard_y_whitespace))
        $OUs_label2.Size = New-Object System.Drawing.Size(($standard_listbox_width/2.8), $standard_label_height)
        $OUs_label2.Font = $standard_font
        $OUs_label2.Text = "Path:"
        $SCRIPT:objForm.Controls.Add($OUs_label2) 

        # creating the fourth list box and adding it to the form (destination OUs)
        $OUs_ListBox2 = New-Object System.Windows.Forms.ListBox 
        $OUs_ListBox2.Location = New-Object System.Drawing.Size(($objListBox2.Location.X + $objListBox2.Size.Width + $standard_x_whitespace), ($objLabel2.location.Y + $objLabel2.Size.Height + $standard_y_whitespace))
        $OUs_ListBox2.Size = New-Object System.Drawing.Size(($standard_listbox_width/2.8), $standard_listbox_height) 
        $OUs_ListBox2.Font = "Lucida Console,7"
        $OUs_ListBox2.SelectionMode = "MultiExtended"
        $OUs_Listbox2.Enabled = $false
        $OUs_to | % { [void] $OUs_ListBox2.Items.Add($_) }
        $SCRIPT:objForm.Controls.Add($OUs_ListBox2)
        
        # creating the fifth label for the fifth list (source group types)
        $grouptypes_label1 = New-Object System.Windows.Forms.Label
        $grouptypes_label1.Location = New-Object System.Drawing.Size(($OUs_label1.Location.X + $OUs_label1.Size.Width + $standard_x_whitespace), $standard_y_whitespace)
        $grouptypes_label1.Size = New-Object System.Drawing.Size(($standard_listbox_width/16), $standard_label_height) 
        $grouptypes_label1.Font = $standard_font
        $grouptypes_label1.Text = "Type:"
        $SCRIPT:objForm.Controls.Add($grouptypes_label1) 
        
        # creating the fifth list box and adding it to the form (source group types)
        $objListBox5 = New-Object System.Windows.Forms.ListBox 
        $objListBox5.Location = New-Object System.Drawing.Size($grouptypes_label1.Location.X, ($grouptypes_label1.location.Y + $grouptypes_label1.Size.Height + $standard_y_whitespace))
        $objListBox5.Size = New-Object System.Drawing.Size(($standard_listbox_width/16), $standard_listbox_height) 
        $objListBox5.Font = "Lucida Console,7"
        $objListbox5.SelectionMode = "MultiExtended"
        $objListbox5.Enabled = $false
        $types_from | % { [void] $objListBox5.Items.Add($_.ToString()[0]) }
        $SCRIPT:objForm.Controls.Add($objListBox5)

        # creating the sixth label for the sixth list (destination group types)
        $grouptypes_label2 = New-Object System.Windows.Forms.Label
        $grouptypes_label2.Location = New-Object System.Drawing.Size(($OUs_label2.Location.X + $OUs_label2.Size.Width + $standard_x_whitespace), ($objListBox5.location.Y + $objListBox5.Size.Height + $standard_y_whitespace))
        $grouptypes_label2.Size = New-Object System.Drawing.Size(($standard_listbox_width/16), $standard_label_height)
        $grouptypes_label2.Font = $standard_font
        $grouptypes_label2.Text = "Type:"
        $SCRIPT:objForm.Controls.Add($grouptypes_label2) 

        # creating the sixth list box and adding it to the form (destination group types)
        $objListBox6 = New-Object System.Windows.Forms.ListBox 
        $objListBox6.Location = New-Object System.Drawing.Size($grouptypes_label2.Location.X, ($grouptypes_label2.location.Y + $grouptypes_label2.Size.Height + $standard_y_whitespace))
        $objListBox6.Size = New-Object System.Drawing.Size(($standard_listbox_width/16), $standard_listbox_height) 
        $objListBox6.Font = "Lucida Console,7"
        $objListbox6.SelectionMode = "MultiExtended"
        $objListbox6.Enabled = $false
        $types_to | % { [void] $objListBox6.Items.Add($_.ToString()[0]) }
        $SCRIPT:objForm.Controls.Add($objListBox6)

        if ($LogonScripts)
          {
            # creating a new, hidden until invoked, form
            Write-Verbose "Creating the secondary scripts form.."
            $sonObjForm = New-Object System.Windows.Forms.Form 
            $sonObjForm.Size = New-Object System.Drawing.Size($child_form_width, $child_form_height)
            $sonObjForm.StartPosition = "CenterScreen"
            $sonObjForm.FormBorderStyle = 'Fixed3D'
            $sonObjForm.MaximizeBox = $false
            $sonObjForm.KeyPreview = $True
            $sonObjForm.Add_KeyDown({ if ($_.KeyCode -eq "Enter") {Clone_Logon_Scripts; $sonobjForm.Close()} })
            $sonobjForm.Add_KeyDown({ if ($_.KeyCode -eq "Escape") {$sonobjForm.Close()} })
            $sonobjForm.Text = "Compare scripts:"

            # creating the first label for the first text box
            Write-Verbose "Creating the buttons, labels and text boxes for the secondary scripts form.."
            $objLabel3 = New-Object System.Windows.Forms.Label
            $objLabel3.Location = New-Object System.Drawing.Size($standard_x_whitespace, $top_label_baseline) 
            $objLabel3.Size = New-Object System.Drawing.Size(($sonobjForm.Size.Width - $standard_x_whitespace*2), $standard_label_height) 
            $from_script = AD-LogonScript $from
            $objLabel3.Font = $standard_font
            $objLabel3.Text = "[SOURCE]: " + $from_script
            $objLabel3.AutoSize = $true
            $sonObjForm.Controls.Add($objLabel3) 

            if ($from_script)
              {    
                # creating the first edit link for the first text box
                Write-Verbose "Creating edit source script link.."
                $editsourcescript_link = New-Object System.Windows.Forms.LinkLabel
                $editsourcescript_link_OnClick = { notepad $from_script }
                $editsourcescript_link.DataBindings.DefaultDataSourceUpdateMode = 0
                $editsourcescript_link.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
                $editsourcescript_link.LinkColor = [System.Drawing.Color]::FromArgb(255,100,100,100)
                $editsourcescript_link.Location = New-Object System.Drawing.Point(($objLabel3.Location.X + $objLabel3.Size.Width),$objLabel3.Location.Y)
                $editsourcescript_link.Name = "editsourcescript_link"
                $editsourcescript_link.Font = $standard_font
                $editsourcescript_link.Size = New-Object System.Drawing.Size(150,16)
                $editsourcescript_link.TabIndex = 1
                $editsourcescript_link.TabStop = $True
                $editsourcescript_link.Text = "[edit with Notepad]"
                $editsourcescript_link.Visible = $true
                $editsourcescript_link.add_Click($editsourcescript_link_OnClick)
                $sonObjForm.Controls.Add($editsourcescript_link)
              }
        
            # creating the first text box and adding it to the form
            $objTextBox = New-Object System.Windows.Forms.TextBox 
            $objTextBox.Location = New-Object System.Drawing.Size($standard_x_whitespace, ($objLabel3.Location.Y + $objLabel3.Height + $standard_y_whitespace))
            $objTextBox.Size = New-Object System.Drawing.Size(($sonobjForm.Size.Width - $standard_x_whitespace*2), $standard_listbox_height)
            $objTextBox.Font = "Lucida Console,7"
            $objTextBox.MultiLine = $True
            $objTextBox.ReadOnly = $True
            $objTextBox.ScrollBars = "Vertical"
            $sonObjForm.Controls.Add($objTextBox) 
            
            if (($from_script -ne "") -and (Test-Path $from_script))
              { 
                Write-Verbose "Reading script of source user.."
                $reader = [System.IO.File]::OpenText($from_script)
                try 
                  {
                    for(;;) 
                      {
                        $line = $reader.ReadLine()
                        if ($line -eq $null) { break }
                        $objTextBox.Lines += $line
                      }
                  }
                finally { $reader.Close() }
              } 
            else 
              { 
                $objTextBox.Text = "<no script>" 
              }
    
            # creating the second label for the second text box
            $objLabel4 = New-Object System.Windows.Forms.Label
            $objLabel4.Location = New-Object System.Drawing.Size($standard_x_whitespace, ($objTextBox.Location.y + $objTextBox.Size.Height + $standard_y_whitespace))
            $objLabel4.Size = New-Object System.Drawing.Size(($sonobjForm.Size.Width - $standard_x_whitespace*2), $standard_label_height) 
            $to_script = AD-LogonScript $to
            $objLabel4.Font = $standard_font
            $objLabel4.Text = "[DESTINATION]: " + $to_script
            $objLabel4.AutoSize = $true
            $sonObjForm.Controls.Add($objLabel4) 

            if ($to_script)
              {
                # creating the second edit link for the second text box
                Write-Verbose "Creating edit target script link.."
                $edittargetscript_link = New-Object System.Windows.Forms.LinkLabel
                $edittargetscript_link_OnClick = { notepad $to_script }
                $edittargetscript_link.DataBindings.DefaultDataSourceUpdateMode = 0
                $edittargetscript_link.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
                $edittargetscript_link.LinkColor = [System.Drawing.Color]::FromArgb(255,100,100,100)
                $edittargetscript_link.Location = New-Object System.Drawing.Point(($objLabel4.Location.X + $objLabel4.Size.Width),$objLabel4.Location.Y)
                $edittargetscript_link.Name = "edittargetscript_link"
                $edittargetscript_link.Font = $standard_font
                $edittargetscript_link.Size = New-Object System.Drawing.Size(150,16)
                $edittargetscript_link.TabIndex = 1
                $edittargetscript_link.TabStop = $True
                $edittargetscript_link.Text = "[edit with Notepad]"
                $edittargetscript_link.Visible = $true
                $edittargetscript_link.add_Click($edittargetscript_link_OnClick)
                $sonObjForm.Controls.Add($edittargetscript_link)
              }

            # creating the second text box and adding it to the form
            $objTextBox2 = New-Object System.Windows.Forms.TextBox
            $objTextBox2.Location = New-Object System.Drawing.Size($standard_x_whitespace, ($objLabel4.Location.y + $objLabel4.Size.Height + $standard_y_whitespace))
            $objTextBox2.Size = New-Object System.Drawing.Size(($sonobjForm.Size.Width - $standard_x_whitespace*2), ($standard_listbox_height - 50)) 
            $objTextBox2.Font = "Lucida Console,7"
            $objTextBox2.MultiLine = $True
            $objTextBox2.ReadOnly = $True
            $objTextBox2.ScrollBars = "Vertical"
            $sonObjForm.Controls.Add($objTextBox2)
            
            if (($to_script -ne "") -and (Test-Path $to_script))
              { 
                Write-Verbose "Reading script of destination user.."
                $reader = [System.IO.File]::OpenText($to_script)
                try 
                  {
                    for(;;) 
                      {
                        $line = $reader.ReadLine()
                        if ($line -eq $null) { break }
                        $objTextBox2.Lines += $line
                      }
                  }
                finally { $reader.Close() }
              } 
            else 
              { 
                $objTextBox2.Text = "<no script>" 
              }

            # creating the Open selected path button
            $openPathButton = New-Object System.Windows.Forms.Button
            $openPathButton.MinimumSize = New-Object System.Drawing.Size($standard_button_width, $standard_button_height)
            $openPathButton.AutoSize = $true
            $openPathButton.Font = $standard_font
            $openPathButton.Text = "Open selected path"
            $openPathButton.Add_Click({ OpenSelectedText })
            $sonObjForm.Controls.Add($openPathButton)
            $openPathButton.Location = New-Object System.Drawing.Size($standard_x_whitespace, $bottom_child_button_baseline)
    
            # creating the Clone logon script button
            $cloneScriptButton = New-Object System.Windows.Forms.Button
            $cloneScriptButton.MinimumSize = New-Object System.Drawing.Size($standard_button_width, $standard_button_height)
            $cloneScriptButton.AutoSize = $true
            $cloneScriptButton.Text = "Clone logon script from source to target"
            $cloneScriptButton.Font = $standard_font
            $cloneScriptButton.Add_Click({ Clone_Logon_Scripts })
            $sonObjForm.Controls.Add($cloneScriptButton)
            $cloneScriptButton.Location = New-Object System.Drawing.Size(($sonObjForm.Size.Width/2 - $cloneScriptButton.Size.Width/2), $bottom_child_button_baseline)
            
            # creating the Logon scripts button
            $ScriptsButton = New-Object System.Windows.Forms.Button
            $ScriptsButton.Size = New-Object System.Drawing.Size(130, ($standard_button_height + 2))
            $ScriptsButton.Location = New-Object System.Drawing.Size(($SCRIPT:objForm.Size.Width - $ScriptsButton.Size.Width - $standard_x_whitespace - 20), $bottom_button_baseline)
            $ScriptsButton.Font = $standard_font
            $ScriptsButton.Text = "Logon scripts"
            $ScriptsButton.Add_Click({ $sonObjForm.Add_Shown({$sonObjForm.Activate()}); [void] $sonObjForm.ShowDialog(); AD-LogonScript $from; AD-LogonScript $to })
            $SCRIPT:objForm.Controls.Add($ScriptsButton)
          }
        
        if ($Calendars)
          {
            # creating a new, hidden until invoked, form
            Write-Verbose "Creating the tertiary, public folders form.."
            $calendars_form = New-Object System.Windows.Forms.Form 
            $calendars_form.Size = New-Object System.Drawing.Size($child_form_width, $child_form_height)
            $calendars_form.StartPosition = "CenterScreen"
            $calendars_form.KeyPreview = $True
            $calendars_form.FormBorderStyle = 'Fixed3D'
            $calendars_form.MaximizeBox = $false
            $calendars_form.Add_KeyDown({ if ($_.KeyCode -eq "Enter") 
                                        { 
                                          Clone_PF_Permissions
                                          $calendars_form.Close()
                                        }
                                     })
            $calendars_form.Add_KeyDown({if ($_.KeyCode -eq "Escape") {$calendars_form.Close()}})
            $calendars_form.Text = "Compare public calendars and public folders in general:"

            # creating the first label for the first list (source calendar permissions)
            Write-Verbose "Creating the buttons, labels and text boxes for the tertiary public folders form.."
            $objLabel5 = New-Object System.Windows.Forms.Label
            $objLabel5.Location = New-Object System.Drawing.Size($standard_x_whitespace, $top_label_baseline) 
            $objLabel5.Size = New-Object System.Drawing.Size($standard_child_label_width, $standard_label_height) 
            $objLabel5.Font = $standard_font
            $objLabel5.Text = "[SOURCE]:"
            $calendars_form.Controls.Add($objLabel5)
        
            # creating the first text box and adding it to the form (source calendar permissions)
            $objTextBox5 = New-Object System.Windows.Forms.TextBox 
            $objTextBox5.Location = New-Object System.Drawing.Size($standard_x_whitespace, ($objLabel5.Location.Y + $objLabel5.Size.Height + $standard_y_whitespace))
            $objTextBox5.Size = New-Object System.Drawing.Size($standard_child_listbox_width, $standard_listbox_height) 
            $objTextBox5.Font = "Lucida Console,7"
            $objTextBox5.MultiLine = $True 
            $objTextBox5.ReadOnly = $True
            $objTextBox5.ScrollBars = "Vertical"
            $calendars_form.Controls.Add($objTextBox5)

            # creating the second label for the second list (destination calendar permissions)
            $objLabel6 = New-Object System.Windows.Forms.Label
            $objLabel6.Location = New-Object System.Drawing.Size($standard_x_whitespace, ($objTextBox5.Location.Y + $objTextBox5.Size.Height + $standard_y_whitespace)) 
            $objLabel6.Size = New-Object System.Drawing.Size($standard_child_label_width, $standard_label_height) 
            $objLabel6.Font = $standard_font
            $objLabel6.Text = "[DESTINATION]:"
            $calendars_form.Controls.Add($objLabel6)
        
            # creating the second text box and adding it to the form (destination calendar permissions)
            $objTextBox6 = New-Object System.Windows.Forms.TextBox
            $objTextBox6.Location = New-Object System.Drawing.Size($standard_x_whitespace, ($objLabel6.Location.Y + $objLabel6.Size.Height + $standard_y_whitespace))
            $objTextBox6.Size = New-Object System.Drawing.Size($standard_child_listbox_width, ($standard_listbox_height - 50)) 
            $objTextBox6.Font = "Lucida Console,7"
            $objTextBox6.MultiLine = $True
            $objTextBox6.ReadOnly = $True
            $objTextBox6.ScrollBars = "Vertical"
            $calendars_form.Controls.Add($objTextBox6)

            # creating the Get permissions button
            $getCalendarPermissionsButton = New-Object System.Windows.Forms.Button
            $getCalendarPermissionsButton.MinimumSize = New-Object System.Drawing.Size($standard_button_width, $standard_button_height)
            $getCalendarPermissionsButton.AutoSize = $true
            $getCalendarPermissionsButton.Font = $standard_font
            $getCalendarPermissionsButton.Text = "Get permissions"
            $getCalendarPermissionsButton.Add_Click({ $getCalendarPermissionsButton.Enabled = $false; $sonProgressBar.Style = 2; Start-Sleep -Seconds 1; Retrieve_PF_Permissions })
            $calendars_form.Controls.Add($getCalendarPermissionsButton)
            $getCalendarPermissionsButton.Location = New-Object System.Drawing.Size($standard_x_whitespace, $bottom_child_button_baseline)

            # creating the Clone calendar permissions button
            $cloneCalendarsButton = New-Object System.Windows.Forms.Button
            $cloneCalendarsButton.MinimumSize = New-Object System.Drawing.Size($standard_button_width, $standard_button_height)
            $cloneCalendarsButton.AutoSize = $true
            $cloneCalendarsButton.Font = $standard_font
            $cloneCalendarsButton.Text = "Copy calendar permissions"
            $cloneCalendarsButton.Add_Click({ Clone_PF_Permissions })
            $cloneCalendarsButton.Enabled = $false
            $calendars_form.Controls.Add($cloneCalendarsButton)
            $cloneCalendarsButton.Location = New-Object System.Drawing.Size(($calendars_form.Size.Width/2 - $cloneCalendarsButton.Size.Width/2), $bottom_child_button_baseline)

            $sonProgressBar = New-Object System.Windows.Forms.ProgressBar
            $sonProgressBar.DataBindings.DefaultDataSourceUpdateMode = 0
            $sonProgressBar.Size = New-Object System.Drawing.Size(($cloneCalendarsButton.Location.X - $standard_x_whitespace * 3 - $getCalendarPermissionsButton.Size.Width), $standard_button_height)
            $sonProgressBar.Location = New-Object System.Drawing.Size(($getCalendarPermissionsButton.Location.X + $getCalendarPermissionsButton.Size.Width + $standard_x_whitespace), $bottom_child_button_baseline)

            $sonProgressBar.Name = "sonProgressBar"
            $sonProgressBar.Style = 1
            $sonProgressBar.TabIndex = 2
            $calendars_form.Controls.Add($sonProgressBar)

            # creating the Calendars button on the main form
            $calendarsButton = New-Object System.Windows.Forms.Button
            $calendarsButton.MinimumSize = New-Object System.Drawing.Size($standard_button_width, $standard_button_height)
            $calendarsButton.AutoSize = $true
            $calendarsButton.Font = $standard_font
            $calendarsButton.Text = "Calendars"
            $calendarsButton.Add_Click({ $calendars_form.Add_Shown({$calendars_form.Activate()}); 
                                         [void] $calendars_form.ShowDialog(); 
                                         $getCalendarPermissionsButton.Enabled = $true;
                                       })
            $SCRIPT:objForm.Controls.Add($calendarsButton)
            $calendarsButton.Location = New-Object System.Drawing.Size($standard_x_whitespace, $bottom_button_baseline)
          }

        $mainProgressBar = New-Object System.Windows.Forms.ProgressBar
        $mainProgressBar.DataBindings.DefaultDataSourceUpdateMode = 0
        $mainProgressBar.Size = New-Object System.Drawing.Size(($OKButton.Location.X - $standard_x_whitespace * 3 - $calendarsButton.Size.Width), $standard_button_height)
        $mainProgressBar.Location = New-Object System.Drawing.Point(($calendarsButton.Location.X + $calendarsButton.Size.Width + $standard_x_whitespace), $bottom_button_baseline)
        $mainProgressBar.Name = "mainProgressBar"
        $mainProgressBar.Style = 1 # blocks (2 = marquee)
        $mainProgressBar.TabIndex = 2
        $SCRIPT:objForm.Controls.Add($mainProgressBar) 

        $wait_for_update_label = New-Object System.Windows.Forms.Label
        $wait_for_update_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $wait_for_update_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,0,0)
        $wait_for_update_label.Location = New-Object System.Drawing.Point(($CancelButton.Location.X + $CancelButton.Size.Width + $standard_x_whitespace),($bottom_button_baseline + 4))
        $wait_for_update_label.Name = "wait_for_update_label"
        $wait_for_update_label.Size = New-Object System.Drawing.Size(224,13)
        $wait_for_update_label.Text = "Waiting 500ms for the domain controller(s) to update.."
        $wait_for_update_label.AutoSize = $True
        $wait_for_update_label.Visible = $false
        $SCRIPT:objForm.Controls.Add($wait_for_update_label)
    
        # displaying the main form
        Write-Verbose "Displaying the main form.."
        $SCRIPT:objForm.Add_Shown({$SCRIPT:objForm.Activate()})
        [void] $SCRIPT:objForm.ShowDialog()
        
        # returning the selected item(s)
        $SCRIPT:listSelItems
      }
        
    function GetMaxItemLength($array)
      {
        $max = 0
        $array | % { if ($_.length -gt $max) { $max = $_.length } }
        $max
      }

    function AppendSpaces([string]$str, [int]$target)
      {
        for ($i=$str.length;$i -lt $target; $i++) { $str += " " }
        $str
      }
 
    function CleanString([string]$str, [int]$target)
      {
        Write-Debug "Input string length: $($str.length)"
        Write-Debug "Substring start: 0"
        Write-Debug "Substring target: $target"
        $str.Substring(0,$target).Trim()
      }

    function GetUserData
      {
        Write-Verbose "Retrieving groups and other user information..."
        $from_values = Get-ADUser $from -Properties MemberOf | Select -ExpandProperty memberof | Sort | % { Get-ADGroup $_ -Properties * | Select Name, Description, GroupCategory, @{N="ParentOU";E={$a = $_.CanonicalName.split("/"); $a[1..($a.Length-2)] -join '/'}} }
        $SCRIPT:max_name_length1 = GetMaxItemLength ($from_values | Select -ExpandProperty Name)
        $SCRIPT:new_from_values = $SCRIPT:OUs_from = $SCRIPT:types_from = @()
        $from_values | % { 
                           if ($_.Description) { $_.Description = " > " + $_.Description }
                           if ($_.name.length -lt $SCRIPT:max_name_length1) 
                             { 
                               $SCRIPT:new_from_values += ((AppendSpaces -str $_.name -target $SCRIPT:max_name_length1) + $_.Description)
                             } 
                           else 
                             { 
                               $SCRIPT:new_from_values += ($_.name + $_.Description) 
                             }
                         }
        
        $from_values | % { $SCRIPT:OUs_from += $_.ParentOU }
        $from_values | % { $SCRIPT:types_from += $_.GroupCategory }
     
        $from_name = Get-ADUser $from | Select -ExpandProperty Name
        $to_name = Get-ADUser $to |  Select -ExpandProperty Name
        
        $to_values = Get-ADUser $to -Properties MemberOf | Select -ExpandProperty MemberOf | Sort | % { Get-ADGroup $_ -Properties * | Select Name, Description, GroupCategory, @{N="ParentOU";E={$a = $_.CanonicalName.split("/"); $a[1..($a.Length-2)] -join '/'}} }
        $SCRIPT:to_count = (Get-ADUser $to -Properties MemberOf | Select -ExpandProperty MemberOf | Measure).Count
        $SCRIPT:max_name_length2 = GetMaxItemLength ($to_values | Select -ExpandProperty Name)
        $SCRIPT:new_to_values = $SCRIPT:OUs_to = $SCRIPT:types_to = @()
        $to_values | % { 
                         if ($_.Description) { $_.Description = " > " + $_.Description }
                         if ($_.name.length -lt $SCRIPT:max_name_length2) 
                           { 
                             $SCRIPT:new_to_values += ((AppendSpaces -str $_.name -target $SCRIPT:max_name_length2) + $_.Description)
                           } 
                         else 
                           { 
                             $SCRIPT:new_to_values += ($_.name + $_.Description) 
                           }
                         }
        $to_values | % { $SCRIPT:OUs_to += $_.ParentOU }
        $to_values | % { $SCRIPT:types_to += $_.GroupCategory }

        $SCRIPT:description1 = "[SOURCE] Select the groups ($(($from_values | Measure).count) total) to copy from user $($from) ($($from_name)):"
        $SCRIPT:description2 = "[TARGET] The groups ($(($to_values | Measure).count) total) of user $($to) ($($to_name)) that will be updated:"

        if ($SCRIPT:new_from_values.count -eq 0) { $SCRIPT:new_from_values += "<no groups (excluding default groups such as Domain Users)>"; $SCRIPT:OUs_from += "<no groups>"; $SCRIPT:types_from += "<no groups>"; }
        if ($SCRIPT:new_to_values.count -eq 0) { $SCRIPT:new_to_values += "<no groups (excluding default groups such as Domain Users)>"; $SCRIPT:OUs_to += "<no groups>"; $SCRIPT:types_to += "<no groups>";  }
      }

    Write-Verbose "Checking existence of source and destination entities in AD.."
    $source_user = Get-ADUser $from
    if ($source_user)
      {
        Write-Verbose "Source user found."
        $dest_user = Get-ADUser $to
        if (!$dest_user)
          {
            Write-Warning "Destination user not found! Exiting!"
            Exit
          }
        Write-Verbose "Destination user found."
      }
    else
      {
        Write-Warning "Source user not found! Exiting!"
        Exit
      }
    
    GetUserData
    $SCRIPT:original_to_count = (Get-ADUser $to -Properties MemberOf | Select -ExpandProperty MemberOf | Measure).Count
    
    $selItems = DoubleSelectionBox -LogonScripts -Calendars
  }

function AD-CompareGroups
  {
    <# .SYNOPSIS
       A simplistic GUI that allows an administrator to compare groups and "copy" members from one group to another.
       Works with groups in the current domain.

       .EXAMPLE
       AD-CompareGroups TestGroup1 TestGroup2
    #>
    
    [cmdletbinding()] param([parameter(Mandatory=$true)] [string]$from, [parameter(Mandatory=$true)] [string]$to)

    function CopyMembers
      {
        $items = $objListbox.SelectedItems
        
        # proceeding to "copy" users from one group to another
        Write-Verbose "User selected $($objListbox.SelectedItems.count) values."
        if ($items.Count -gt 0) 
          { 
            $mainProgressBar.Value = 0
            $mainProgressBar.Step = ($mainProgressBar.Maximum / $items.Count)
            ForEach ($item in $items)
              { 
                 Write-Verbose "Adding users to target group.."
                 $entity = CleanString -str $item -target ($max_name_length1)
                 Write-Verbose "Adding user $($entity).."
                 Add-ADGroupMember $to $entity

                 $SCRIPT:listSelItems += $item; 
                 $mainProgressBar.PerformStep()
              }
            $mainProgressBar.Value = $mainProgressBar.Maximum
            UI-MessageBox "Done (hopefully without errors). Close this program and run it again to check."
          }
        else
          {
            UI-MessageBox "Select at least one user please."
          }
        
        # $SCRIPT:objForm.Close() -> refresh form!
      }

    function UpdateUI
      {
        Write-Verbose "Updating the UI.."
        
        # updating the first list box (source groups)
        $objListBox.Items.Clear()
        $new_from_values | % { [void] $objListBox.Items.Add($_) }
        
        # updating the second list box (destination groups)
        $objListBox2.Items.Clear()
        $new_to_values | % { [void] $objListBox2.Items.Add($_) }
        
        # updating the third list box (source OUs)
        $OUs_ListBox1.Items.Clear()
        $OUs_from | % { [void] $OUs_ListBox1.Items.Add($_) }

        # updating the fourth list box (destination OUs)
        $OUs_ListBox2.Items.Clear()
        $OUs_to | % { [void] $OUs_ListBox2.Items.Add($_) }
        
        # updating the fifth list box (source group types)
        $objListBox5.Items.Clear()
        $types_from | % { [void] $objListBox5.Items.Add($_.ToString()[0]) }

        # updating the sixth list box (destination group types)
        $objListBox6.Items.Clear()
        $types_to | % { [void] $objListBox6.Items.Add($_.ToString()[0]) }

        $mainProgressBar.Value = 0
        $objLabel.ForeColor = [System.Drawing.Color]::FromArgb(255,0,0,0)
        $objLabel2.ForeColor = [System.Drawing.Color]::FromArgb(255,0,0,0)
      }

    function UsersDiff
      {
        if ($DiffButton.Text -eq "Diff")
          {
            Write-Verbose "Calculating differences..."
            $clean_from_values = @()
            $new_from_values | % { $clean_from_values += ($_ -split '>')[0].Trim() }
            Write-Verbose "Cleaned from values:"
            $clean_from_values | % { Write-Verbose $_ }
            $clean_to_values = @()
            $new_to_values | % { $clean_to_values += ($_ -split '>')[0].Trim() }
            Write-Verbose "Cleaned to values:"
            $clean_to_values | % { Write-Verbose $_ }
    
            $objListBox.Items.Clear()
            $objListBox2.Items.Clear()
            $OUs_ListBox1.Items.Clear()
            $OUs_ListBox2.Items.Clear()
            $objListBox5.Items.Clear()
            $objListBox6.Items.Clear()
    
            $i = 0
            $clean_from_values | % { 
                                     if ($clean_to_values -notcontains $_) 
                                       { 
                                         Write-Verbose "$_ is only a member of source group, adding it to diff list.."
                                         Write-Verbose "Adding: $($new_from_values[$i])"
                                         $objListBox.Items.Add($new_from_values[$i])
                                         $OUs_ListBox1.Items.Add($OUs_from[$i])
                                         $objListBox5.Items.Add($types_from[$i].ToString()[0])
                                         
                                       }
                                     $i++
                                   }
            $DiffButton.Text = "Full"

            $objLabel.ForeColor = [System.Drawing.Color]::FromArgb(255,255,0,0)
            $objLabel2.ForeColor = [System.Drawing.Color]::FromArgb(255,255,0,0)
          }
        else
          {
            Write-Verbose "Restoring users..."
            UpdateUI
            $DiffButton.Text = "Diff"
          }
      }

    function DoubleSelectionBox($from, $to, $items1, $description1, $items2, $description2)
      {
        $SCRIPT:listSelItems = @()
    
        # loading .NET framework classes
        Write-Verbose "Creating the UI.."
        Write-Verbose "Loading .NET framework classes.."
        [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
        [System.Windows.Forms.Application]::EnableVisualStyles()
    
        # setting a few "standard" parameters
        [int] $standard_form_height = 600
        [int] $standard_form_width = 1195
        [int] $child_form_height = $standard_form_height - 50
        [int] $child_form_width = $standard_form_width - 50
        [int] $standard_button_height = 23
        [int] $standard_button_width = 75
        [int] $standard_label_height = 20
        [int] $standard_label_width = [int] $standard_listbox_width = 815
        [int] $standard_child_label_width = [int] $standard_child_listbox_width = $child_form_width - ($standard_x_whitespace * 2) - 30
        [int] $standard_listbox_height = 235
        [int] $standard_y_whitespace = [int] $standard_x_whitespace = 5
        [int] $bottom_button_baseline = $standard_form_height - $standard_button_height - $standard_y_whitespace - 40
        [int] $bottom_child_button_baseline = $child_form_height - $standard_button_height - $standard_y_whitespace - 40
        [int] $top_label_baseline =  $standard_y_whitespace
        $standard_font = New-Object System.Drawing.Font("Gill Sans MT",9.75,1,3,0)

        # creating the main form
        Write-Verbose "Creating the main form.."
        $SCRIPT:objForm = New-Object System.Windows.Forms.Form 
        $SCRIPT:objForm.Size = New-Object System.Drawing.Size($standard_form_width, $standard_form_height)
        $SCRIPT:objForm.StartPosition = "CenterScreen"
        $SCRIPT:objForm.FormBorderStyle = 'Fixed3D'
        $SCRIPT:objForm.MaximizeBox = $false
        $SCRIPT:objForm.KeyPreview = $True
        $SCRIPT:objForm.Add_KeyDown({if ($_.KeyCode -eq "Enter") { CopyMembers }})
        $SCRIPT:objForm.Add_KeyDown({if ($_.KeyCode -eq "Escape") { $SCRIPT:objForm.Close() }})
        
        # setting variable parameters for the form
        $SCRIPT:objForm.Text = "Make a selection and click COPY!"

        Write-Verbose "Creating buttons, list boxes and labels in the main form.."
        
        # creating the OK button
        $OKButton = New-Object System.Windows.Forms.Button
        $OKButton.Location = New-Object System.Drawing.Size(($standard_form_width/2 - $standard_button_width - $standard_x_whitespace), $bottom_button_baseline)
        $OKButton.Size = New-Object System.Drawing.Size($standard_button_width, $standard_button_height)
        $OKButton.Font = $standard_font
        $OKButton.Text = "COPY!"
        $OKButton.Add_Click({ CopyMembers })
        $SCRIPT:objForm.Controls.Add($OKButton)
        
        # creating the Cancel button
        $CancelButton = New-Object System.Windows.Forms.Button
        $CancelButton.Location = New-Object System.Drawing.Size(($standard_form_width/2 + $standard_x_whitespace), $bottom_button_baseline)
        $CancelButton.Size = New-Object System.Drawing.Size($standard_button_width, $standard_button_height)
        $CancelButton.Font = $standard_font
        $CancelButton.Text = "Cancel.."
        $CancelButton.Add_Click({$SCRIPT:objForm.Close()})
        $SCRIPT:objForm.Controls.Add($CancelButton)

        # creating the Diff button
        $DiffButton = New-Object System.Windows.Forms.Button
        $DiffButton.Location = New-Object System.Drawing.Point(($standard_form_width * 0.8), $bottom_button_baseline)
        $DiffButton.Size = New-Object System.Drawing.Size($standard_button_width, $standard_button_height)
        $DiffButton.Font = $standard_font
        $DiffButton.Text = "Diff"
        $DiffButton.Add_Click({ UsersDiff })
        $SCRIPT:objForm.Controls.Add($DiffButton)

        # creating the first label for the first list and adding it to the form (source groups)
        $objLabel = New-Object System.Windows.Forms.Label
        $objLabel.Location = New-Object System.Drawing.Size($standard_x_whitespace, $top_label_baseline) 
        $objLabel.Size = New-Object System.Drawing.Size($standard_label_width, $standard_label_height)
        $objLabel.Font = $standard_font
        $objLabel.Text = $description1
        $SCRIPT:objForm.Controls.Add($objLabel) 
        
        # creating the first list box and adding it to the form (source groups)
        $objListBox = New-Object System.Windows.Forms.ListBox 
        $objListBox.Location = New-Object System.Drawing.Size($standard_x_whitespace, ($objLabel.location.Y + $objLabel.Size.Height + $standard_y_whitespace)) 
        $objListBox.Size = New-Object System.Drawing.Size($standard_listbox_width, $standard_listbox_height) 
        $objListBox.Font = "Lucida Console,7"
        $objListbox.SelectionMode = "MultiExtended"
        $items1 | % { [void] $objListBox.Items.Add($_) }
        $SCRIPT:objForm.Controls.Add($objListBox) 
        $objListbox.Add_Click({ $OUs_ListBox1.ClearSelected(); $objListBox5.ClearSelected(); 
                                $objListBox.SelectedIndices | % { $OUs_ListBox1.SelectedIndex = $objListBox5.SelectedIndex = $objListbox.SelectedIndex = $_ } })
    
        # creating the second label for the second list
        $objLabel2 = New-Object System.Windows.Forms.Label
        $objLabel2.Location = New-Object System.Drawing.Size($standard_x_whitespace, ($objListBox.location.Y + $objListBox.Size.Height + $standard_y_whitespace)) 
        $objLabel2.Size = New-Object System.Drawing.Size($standard_label_width, $standard_label_height)
        $objLabel2.Font = $standard_font
        $objLabel2.Text = $description2
        $SCRIPT:objForm.Controls.Add($objLabel2) 
        
        # creating the second list box and adding it to the form
        $objListBox2 = New-Object System.Windows.Forms.ListBox 
        $objListBox2.Location = New-Object System.Drawing.Size($standard_x_whitespace, ($objLabel2.location.Y + $objLabel2.Size.Height + $standard_y_whitespace)) 
        $objListBox2.Size = New-Object System.Drawing.Size($standard_listbox_width, $standard_listbox_height) 
        $objListBox2.Font = "Lucida Console,7"
        $objListbox2.SelectionMode = "MultiExtended"
        $items2 | % { [void] $objListBox2.Items.Add($_) }
        $SCRIPT:objForm.Controls.Add($objListBox2)
        $objListbox2.Add_Click({ $OUs_ListBox2.ClearSelected(); $objListBox6.ClearSelected(); 
                                 $objListBox2.SelectedIndices | % { $OUs_ListBox2.SelectedIndex = $objListBox6.SelectedIndex = $objListbox2.SelectedIndex = $_ } })
        

        # creating the third label for the third list (source OUs)
        $OUs_label1 = New-Object System.Windows.Forms.Label
        $OUs_label1.Location = New-Object System.Drawing.Size(($objLabel.Location.X + $objLabel.Size.Width + $standard_x_whitespace), $standard_y_whitespace)
        $OUs_label1.Size = New-Object System.Drawing.Size(($standard_listbox_width/4), $standard_label_height)
        $OUs_label1.Font = $standard_font
        $OUs_label1.Text = "Path:"
        $SCRIPT:objForm.Controls.Add($OUs_label1)
        
        # creating the third list box and adding it to the form (source OUs)
        $OUs_ListBox1 = New-Object System.Windows.Forms.ListBox 
        $OUs_ListBox1.Location = New-Object System.Drawing.Size($OUs_label1.Location.X, ($OUs_label1.location.Y + $OUs_label1.Size.Height + $standard_y_whitespace))
        $OUs_ListBox1.Size = New-Object System.Drawing.Size(($standard_listbox_width/4), $standard_listbox_height) 
        $OUs_ListBox1.Font = "Lucida Console,7"
        $OUs_ListBox1.SelectionMode = "MultiExtended"
        $OUs_Listbox1.Enabled = $false
        $OUs_from | % { [void] $OUs_ListBox1.Items.Add($_) }
        $SCRIPT:objForm.Controls.Add($OUs_ListBox1)

        # creating the fourth label for the fourth list (destination OUs)
        $OUs_label2 = New-Object System.Windows.Forms.Label
        $OUs_label2.Location = New-Object System.Drawing.Size($OUs_label1.Location.X, ($OUs_ListBox1.location.Y + $OUs_ListBox1.Size.Height + $standard_y_whitespace))
        $OUs_label2.Size = New-Object System.Drawing.Size(($standard_listbox_width/4), $standard_label_height)
        $OUs_label2.Font = $standard_font
        $OUs_label2.Text = "Path:"
        $SCRIPT:objForm.Controls.Add($OUs_label2) 

        # creating the fourth list box and adding it to the form (destination OUs)
        $OUs_ListBox2 = New-Object System.Windows.Forms.ListBox 
        $OUs_ListBox2.Location = New-Object System.Drawing.Size(($objListBox2.Location.X + $objListBox2.Size.Width + $standard_x_whitespace), ($objLabel2.location.Y + $objLabel2.Size.Height + $standard_y_whitespace))
        $OUs_ListBox2.Size = New-Object System.Drawing.Size(($standard_listbox_width/4), $standard_listbox_height) 
        $OUs_ListBox2.Font = "Lucida Console,7"
        $OUs_ListBox2.SelectionMode = "MultiExtended"
        $OUs_Listbox2.Enabled = $false
        $OUs_to | % { [void] $OUs_ListBox2.Items.Add($_) }
        $SCRIPT:objForm.Controls.Add($OUs_ListBox2)
        
        # creating the fifth label for the fifth list (source group types)
        $grouptypes_label1 = New-Object System.Windows.Forms.Label
        $grouptypes_label1.Location = New-Object System.Drawing.Size(($OUs_label1.Location.X + $OUs_label1.Size.Width + $standard_x_whitespace), $standard_y_whitespace)
        $grouptypes_label1.Size = New-Object System.Drawing.Size(($standard_listbox_width/6), $standard_label_height) 
        $grouptypes_label1.Font = $standard_font
        $grouptypes_label1.Text = "Company:"
        $SCRIPT:objForm.Controls.Add($grouptypes_label1) 
        
        # creating the fifth list box and adding it to the form (source group types)
        $objListBox5 = New-Object System.Windows.Forms.ListBox 
        $objListBox5.Location = New-Object System.Drawing.Size($grouptypes_label1.Location.X, ($grouptypes_label1.location.Y + $grouptypes_label1.Size.Height + $standard_y_whitespace))
        $objListBox5.Size = New-Object System.Drawing.Size(($standard_listbox_width/6), $standard_listbox_height) 
        $objListBox5.Font = "Lucida Console,7"
        $objListbox5.SelectionMode = "MultiExtended"
        $objListbox5.Enabled = $false
        $types_from | % { [void] $objListBox5.Items.Add($_) }
        $SCRIPT:objForm.Controls.Add($objListBox5)

        # creating the sixth label for the sixth list (destination group types)
        $grouptypes_label2 = New-Object System.Windows.Forms.Label
        $grouptypes_label2.Location = New-Object System.Drawing.Size(($OUs_label2.Location.X + $OUs_label2.Size.Width + $standard_x_whitespace), ($objListBox5.location.Y + $objListBox5.Size.Height + $standard_y_whitespace))
        $grouptypes_label2.Size = New-Object System.Drawing.Size(($standard_listbox_width/6), $standard_label_height)
        $grouptypes_label2.Font = $standard_font
        $grouptypes_label2.Text = "Company:"
        $SCRIPT:objForm.Controls.Add($grouptypes_label2) 

        # creating the sixth list box and adding it to the form (destination group types)
        $objListBox6 = New-Object System.Windows.Forms.ListBox 
        $objListBox6.Location = New-Object System.Drawing.Size($grouptypes_label2.Location.X, ($grouptypes_label2.location.Y + $grouptypes_label2.Size.Height + $standard_y_whitespace))
        $objListBox6.Size = New-Object System.Drawing.Size(($standard_listbox_width/6), $standard_listbox_height) 
        $objListBox6.Font = "Lucida Console,7"
        $objListbox6.SelectionMode = "MultiExtended"
        $objListbox6.Enabled = $false
        $types_to | % { [void] $objListBox6.Items.Add($_) }
        $SCRIPT:objForm.Controls.Add($objListBox6)

        $mainProgressBar = New-Object System.Windows.Forms.ProgressBar
        $mainProgressBar.DataBindings.DefaultDataSourceUpdateMode = 0
        $mainProgressBar.Size = New-Object System.Drawing.Size(($OKButton.Location.X - $standard_x_whitespace * 2), $standard_button_height)
        $mainProgressBar.Location = New-Object System.Drawing.Point($standard_x_whitespace, $bottom_button_baseline)
        $mainProgressBar.Name = "mainProgressBar"
        $mainProgressBar.Style = 1 # blocks (2 = marquee)
        $mainProgressBar.TabIndex = 2
        $SCRIPT:objForm.Controls.Add($mainProgressBar) 
    
        # displaying the main form
        Write-Verbose "Displaying the main form.."
        $SCRIPT:objForm.Add_Shown({$SCRIPT:objForm.Activate()})
        [void] $SCRIPT:objForm.ShowDialog()
        
        # returning the selected item(s)
        $SCRIPT:listSelItems
      }
        
    function GetMaxItemLength($array)
      {
        $max = 0
        $array | % { if ($_.length -gt $max) { $max = $_.length } }
        $max
      }

    function AppendSpaces([string]$str, [int]$target)
      {
        for ($i=$str.length;$i -lt $target; $i++) { $str += " " }
        $str
      }
 
    function CleanString([string]$str, [int]$target)
      {
        Write-Debug "Input string length: $($str.length)"
        Write-Debug "Substring start: 0"
        Write-Debug "Substring target: $target"
        $str.Substring(0,$target).Trim()
      }

    Write-Verbose "Checking existence of source and destination entities in AD.."
    $source_user = Get-ADGroup -Identity $from
    if ($source_user)
      {
        Write-Verbose "Source group found."
        $dest_user = Get-ADGroup -Identity $to
        if (!$dest_user)
          {
            Write-Warning "Destination group not found! Exiting!"
            Exit
          }
        Write-Verbose "Destination group found."
      }
    else
      {
        Write-Warning "Source group not found! Exiting!"
        Exit
      }
    
    Write-Verbose "Retrieving groups and other information..."

    # $from_values = Get-ADGroup -Identity $from -Properties * | Select -ExpandProperty Members | Sort | % { Get-ADUser $_ -Properties * | Select Name, SamAccountName, Company, @{N="ParentOU";E={$a = $_.CanonicalName.split("/"); $a[1..($a.Length-2)] -join '/'}}, Description }

    $members = Get-ADGroup -Identity $from -Properties * | Select -ExpandProperty Members | Sort 
    $from_values = @()
    $members | % { 
                   $obj = Get-ADObject -Identity $_
                   if ($obj.ObjectClass -eq "group")
                     {
                       $from_values += Get-ADGroup $_ -Properties * | Select Name, DisplayName, @{N="Company";E={"N/A"}}, @{N="ParentOU";E={$a = $_.CanonicalName.split("/"); $a[1..($a.Length-2)] -join '/'}}, Description 
                     }
                   else
                     {
                       $from_values += Get-ADUser $_ -Properties * | Select Name, SamAccountName, Company, @{N="ParentOU";E={$a = $_.CanonicalName.split("/"); $a[1..($a.Length-2)] -join '/'}}, Description 
                     }
                 }
    $max_name_length1 = GetMaxItemLength ($from_values | Select -ExpandProperty Name)
    $new_from_values = $OUs_from = $types_from = @()
    $from_values | % { 
                       if ($_.Description) { $_.Description = " > " + $_.Description }
                       if ($_.name.length -lt $max_name_length1) 
                         { 
                           $new_from_values += ((AppendSpaces -str $_.name -target $max_name_length1) + $_.Description)
                         } 
                       else 
                         { 
                           $new_from_values += ($_.name + $_.Description) 
                         }
                     }

    $from_values | % { $OUs_from += $_.ParentOU }
    $from_values | % { if ($_.Company) { $types_from += $_.Company } else { $types_from += "N/D" } }
    
    $members2 = Get-ADGroup -Identity $to -Properties * | Select -ExpandProperty Members | Sort 
    $to_values = @()
    $members2 | % { 
                    $obj = Get-ADObject -Identity $_
                    if ($obj.ObjectClass -eq "group")
                      {
                        $to_values += Get-ADGroup $_ -Properties * | Select Name, DisplayName, @{N="Company";E={"N/A"}}, @{N="ParentOU";E={$a = $_.CanonicalName.split("/"); $a[1..($a.Length-2)] -join '/'}}, Description 
                      }
                    else
                      {
                        $to_values += Get-ADUser $_ -Properties * | Select Name, SamAccountName, Company, @{N="ParentOU";E={$a = $_.CanonicalName.split("/"); $a[1..($a.Length-2)] -join '/'}}, Description 
                      }
                  }
    $max_name_length2 = GetMaxItemLength ($to_values | Select -ExpandProperty Name)
    $new_to_values = $OUs_to = $types_to = @()
    $to_values | % { 
                     if ($_.Description) { $_.Description = " > " + $_.Description }
                     if ($_.name.length -lt $max_name_length2) 
                       { 
                         $new_to_values += ((AppendSpaces -str $_.name -target $max_name_length2) + $_.Description)
                       } 
                     else 
                       { 
                         $new_to_values += ($_.name + $_.Description) 
                       }
                   }
    $to_values | % { $OUs_to += $_.ParentOU }
    $to_values | % { if ($_.Company) { $types_to += $_.Company } else { $types_to += "N/D" } }
    
    $description1 = "[SOURCE] Select the members ($(($from_values | Measure).count) total) to copy from group $($from):"
    $description2 = "[TARGET] These are the members ($(($to_values | Measure).count) total) of group $($to) that will be updated:"

    if ($new_from_values.count -eq 0) { $new_from_values += "<no users>"; $OUs_from += "<no users>"; $types_from += "<no users>"; }
    if ($new_to_values.count -eq 0) { $new_to_values += "<no users>"; $OUs_to += "<no users>"; $types_to += "<no users>";  }
    $selItems = DoubleSelectionBox $from $to $new_from_values $description1 $new_to_values $description2
  }

function AD-RemoveUserGroups
  {
    <# .SYNOPSIS
       A simplistic GUI that allows an administrator to review and remove groups from the membership of any domain user (depending on permissions).
       Works with the current domain.

       .EXAMPLE
       AD-RemoveUserGroups TestUser
    #>
    
    [cmdletbinding()] param([parameter(Mandatory=$true)] [string]$from)

    function RemoveGroups
      {
        $items = $objListbox.SelectedItems
        
        # proceeding to "copy" groups from one user to another
        Write-Verbose "User selected $($objListbox.SelectedItems.count) values."
        if ($items.Count -gt 0) 
          { 
            $OKButton.Enabled = $false
            $mainProgressBar.Visible = $true
            $mainProgressBar.Value = 0
            $mainProgressBar.Step = ($mainProgressBar.Maximum / $items.Count)
            ForEach ($item in $items)
              { 
                 Write-Verbose "Removing user from selected groups.."
                 $group = CleanString -str $item -target ($max_name_length1)
                 Write-Verbose "Removing user from $($group).."
                 Remove-ADGroupMember -Identity $group -Member $from -Confirm:$False

                 $SCRIPT:listSelItems += $item; 
                 $mainProgressBar.PerformStep()
              }
            $mainProgressBar.Value = $mainProgressBar.Maximum
            UI-MessageBox "Done (hopefully without errors). Close this program and run it again to check."
            $OKButton.Enabled = $true
          }
        else
          {
            UI-MessageBox "Select at least one group please."
          }
      }

    function AddGroups
      {
        $items = $group_finder_listBox.SelectedItems
        
        # proceeding to add groups to the user's membership
        Write-Verbose "User selected $($group_finder_listBox.SelectedItems.count) values."
        if ($items.Count -gt 0) 
          { 
            $childOKButton.Enabled = $false
            $childProgressBar.Visible = $true
            $childProgressBar.Value = 0
            $childProgressBar.Step = ($childProgressBar.Maximum / $items.Count)
            ForEach ($item in $items)
              { 
                 Write-Verbose "Adding user to selected groups.."
                 $group = CleanString -str $item -target ($SCRIPT:max_group_name_length)
                 Write-Verbose "Adding user to $($group).."
                 Add-ADGroupMember -Identity $group -Members $from -Confirm:$False
                 $childProgressBar.PerformStep()
              }
            $childProgressBar.Value = $childProgressBar.Maximum
            UI-MessageBox "Done (hopefully without errors). Close this program and run it again to check."
          }
        else
          {
            UI-MessageBox "Select at least one group please."
          }
      }

    function FindGroups([string]$str)
      {
        $group_finder_button.Enabled = $false
        $group_finder_listBox.Items.Clear()
        $group_finder_listBox.Visible = $false
        $childProgressBar.Visible = $false
        $Identity = "*$($str)*"
        Write-Verbose "Searching groups using string: $str"
        $Group = Get-ADGroup -Properties * -Filter {(Name -like $Identity) -or (SamAccountName -like $Identity) -or (DisplayName -like $Identity) -or (DistinguishedName -like $Identity) -or (CN -like $Identity)}
        Write-Verbose "Found $(($Group | measure).count) results"
        if (($Group | measure).count)
          {
            Write-Verbose "Found $(($Group | measure).count) groups. Adding them to results listbox."
            $group_finder_listBox.Visible = $true
            $childOKButton.Enabled = $true
            $new_values = @()
            $Group | % { 
                         Write-Verbose "Found group: $($_.SamAccountName)`t`t$($_.Name)"
                         $SCRIPT:max_group_name_length = GetMaxItemLength ($Group | Select -ExpandProperty Name)
                         if ($_.name.length -lt $SCRIPT:max_group_name_length) 
                           { 
                             $a = $_.CanonicalName.split("/")
                             $path = $a[1..($a.Length-2)] -join '/'
                             $new_values += ((AppendSpaces -str $_.name -target $SCRIPT:max_group_name_length) + " - path: $path")
                           } 
                         else 
                           { 
                             $new_values += ($_.name + " - path: $($_.CanonicalName)") 
                           }
                       }
            $new_values | % { [void] $group_finder_listBox.Items.Add($_) }
          }
        else 
          {
            UI-MessageBox "Found nothing!"
            $childOKButton.Enabled = $false
          }
        $group_finder_button.Enabled = $true
      }

    function SelectionBox($from, $items1, $description1)
      {
        $SCRIPT:listSelItems = @()
    
        # loading .NET framework classes
        Write-Verbose "Creating the UI.."
        Write-Verbose "Loading .NET framework classes.."
        [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
        [System.Windows.Forms.Application]::EnableVisualStyles()
    
        # setting a few "standard" parameters
        [int] $standard_form_height = 600
        [int] $standard_form_width = 1195
        [int] $child_form_height = $standard_form_height - 50
        [int] $child_form_width = $standard_form_width - 50
        [int] $standard_button_height = 23
        [int] $standard_button_width = 150
        [int] $standard_label_height = 20
        [int] $standard_label_width = [int] $standard_listbox_width = 815
        [int] $standard_listbox_height = $standard_form_height - $standard_button_height - $standard_label_height - ($standard_y_whitespace * 4) - 68
        [int] $standard_y_whitespace = [int] $standard_x_whitespace = 5
        [int] $bottom_button_baseline = $standard_form_height - $standard_button_height - $standard_y_whitespace - 40
        [int] $bottom_child_button_baseline = $child_form_height - $standard_button_height - $standard_y_whitespace - 40
        [int] $top_label_baseline =  $standard_y_whitespace
        $standard_font = New-Object System.Drawing.Font("Gill Sans MT",9.75,1,3,0)

        # creating the main form
        Write-Verbose "Creating the main form.."
        $SCRIPT:objForm = New-Object System.Windows.Forms.Form 
        $SCRIPT:objForm.Size = New-Object System.Drawing.Size($standard_form_width, $standard_form_height)
        $SCRIPT:objForm.StartPosition = "CenterScreen"
        $SCRIPT:objForm.FormBorderStyle = 'Fixed3D'
        $SCRIPT:objForm.MaximizeBox = $false
        $SCRIPT:objForm.KeyPreview = $True
        $SCRIPT:objForm.Add_KeyDown({if ($_.KeyCode -eq "Enter") {RemoveGroups}})
        $SCRIPT:objForm.Add_KeyDown({if ($_.KeyCode -eq "Escape") {$SCRIPT:objForm.Close()}})
        
        # setting variable parameters for the form
        $SCRIPT:objForm.Text = "Make a selection and click Go!"

        Write-Verbose "Creating buttons, list boxes and labels in the main form.."
        
        # creating the OK button
        $OKButton = New-Object System.Windows.Forms.Button
        $OKButton.Location = New-Object System.Drawing.Size(($standard_form_width/2 - $standard_button_width - $standard_x_whitespace), $bottom_button_baseline)
        $OKButton.Size = New-Object System.Drawing.Size($standard_button_width, $standard_button_height)
        $OKButton.Text = "Remove selected"
        $OKButton.Font = $standard_font
        $OKButton.Add_Click({ RemoveGroups })
        $SCRIPT:objForm.Controls.Add($OKButton)
        
        # creating the Cancel button
        $CancelButton = New-Object System.Windows.Forms.Button
        $CancelButton.Location = New-Object System.Drawing.Size(($standard_form_width/2 + $standard_x_whitespace), $bottom_button_baseline)
        $CancelButton.Size = New-Object System.Drawing.Size($standard_button_width, $standard_button_height)
        $CancelButton.Text = "Cancel"
        $CancelButton.Font = $standard_font
        $CancelButton.Add_Click({$SCRIPT:objForm.Close()})
        $SCRIPT:objForm.Controls.Add($CancelButton)

        # creating the first label for the first list and adding it to the form (source groups)
        $objLabel = New-Object System.Windows.Forms.Label
        $objLabel.Location = New-Object System.Drawing.Size($standard_x_whitespace, $top_label_baseline) 
        $objLabel.Size = New-Object System.Drawing.Size($standard_label_width, $standard_label_height) 
        $objLabel.Text = $description1
        $objLabel.Font = $standard_font
        $SCRIPT:objForm.Controls.Add($objLabel) 
        
        # creating the first list box and adding it to the form (source groups)
        $objListBox = New-Object System.Windows.Forms.ListBox 
        $objListBox.Location = New-Object System.Drawing.Size($standard_x_whitespace, ($objLabel.location.Y + $objLabel.Size.Height + $standard_y_whitespace)) 
        $objListBox.Size = New-Object System.Drawing.Size($standard_listbox_width, $standard_listbox_height) 
        $objListBox.Font = "Lucida Console,7"
        $objListbox.SelectionMode = "MultiExtended"
        $items1 | % { [void] $objListBox.Items.Add($_) }
        $SCRIPT:objForm.Controls.Add($objListBox) 
        $objListbox.Add_Click({ $OUs_ListBox1.ClearSelected(); $objListBox5.ClearSelected(); 
                                $objListBox.SelectedIndices | % { $OUs_ListBox1.SelectedIndex = $objListBox5.SelectedIndex = $objListbox.SelectedIndex = $_ } })
    
        # creating the third label for the third list (source OUs)
        $OUs_label1 = New-Object System.Windows.Forms.Label
        $OUs_label1.Location = New-Object System.Drawing.Size(($objLabel.Location.X + $objLabel.Size.Width + $standard_x_whitespace), $standard_y_whitespace)
        $OUs_label1.Size = New-Object System.Drawing.Size(($standard_listbox_width/2.8), $standard_label_height) 
        $OUs_label1.Text = "Path:"
        $OUs_label1.Font = $standard_font
        $SCRIPT:objForm.Controls.Add($OUs_label1)
        
        # creating the third list box and adding it to the form (source OUs)
        $OUs_ListBox1 = New-Object System.Windows.Forms.ListBox 
        $OUs_ListBox1.Location = New-Object System.Drawing.Size($OUs_label1.Location.X, ($OUs_label1.location.Y + $OUs_label1.Size.Height + $standard_y_whitespace))
        $OUs_ListBox1.Size = New-Object System.Drawing.Size(($standard_listbox_width/2.8), $standard_listbox_height) 
        $OUs_ListBox1.Font = "Lucida Console,7"
        $OUs_ListBox1.SelectionMode = "MultiExtended"
        $OUs_Listbox1.Enabled = $false
        $OUs_from | % { [void] $OUs_ListBox1.Items.Add($_) }
        $SCRIPT:objForm.Controls.Add($OUs_ListBox1)
        
        # creating the fifth label for the fifth list (source group types)
        $grouptypes_label1 = New-Object System.Windows.Forms.Label
        $grouptypes_label1.Location = New-Object System.Drawing.Size(($OUs_label1.Location.X + $OUs_label1.Size.Width + $standard_x_whitespace), $standard_y_whitespace)
        $grouptypes_label1.Size = New-Object System.Drawing.Size(($standard_listbox_width/16.6), $standard_label_height) 
        $grouptypes_label1.Text = "Type:"
        $grouptypes_label1.Font = $standard_font
        $SCRIPT:objForm.Controls.Add($grouptypes_label1) 
        
        # creating the fifth list box and adding it to the form (source group types)
        $objListBox5 = New-Object System.Windows.Forms.ListBox 
        $objListBox5.Location = New-Object System.Drawing.Size($grouptypes_label1.Location.X, ($grouptypes_label1.location.Y + $grouptypes_label1.Size.Height + $standard_y_whitespace))
        $objListBox5.Size = New-Object System.Drawing.Size(($standard_listbox_width/16.6), $standard_listbox_height) 
        $objListBox5.Font = "Lucida Console,7"
        $objListbox5.SelectionMode = "MultiExtended"
        $objListbox5.Enabled = $false
        $types_from | % { [void] $objListBox5.Items.Add($_.ToString()[0]) }
        $SCRIPT:objForm.Controls.Add($objListBox5)

        # creating the Add button that spawns the child form for adding groups
        $addButton = New-Object System.Windows.Forms.Button
        $addButton.Size = New-Object System.Drawing.Size(130, ($standard_button_height + 2))
        $addButton.Location = New-Object System.Drawing.Size(($standard_form_width - $addButton.Size.Width - $standard_x_whitespace * 5), ($bottom_button_baseline - 2))
        $addButton.Font = $standard_font
        $addButton.Text = "Add to group(s).."
        $addButton.Add_Click({ $sonObjForm.Add_Shown({$sonObjForm.Activate()}); [void] $sonObjForm.ShowDialog(); })
        $SCRIPT:objForm.Controls.Add($addButton)

        # creating a new, hidden until invoked, form
        Write-Verbose "Creating the Add to groups form.."
        $sonObjForm = New-Object System.Windows.Forms.Form
        $sonObjForm.Size = New-Object System.Drawing.Size($child_form_width, $child_form_height)
        $sonObjForm.StartPosition = "CenterScreen"
        $sonObjForm.FormBorderStyle = 'Fixed3D'
        $sonObjForm.MaximizeBox = $false
        $sonObjForm.KeyPreview = $True
        $sonobjForm.Add_KeyDown({ if ($_.KeyCode -eq "Escape") {$sonobjForm.Close()} })
        $sonobjForm.Text = "Add user to group(s)"

        Write-Verbose "Creating child form buttons, list boxes and labels.."
        
        # creating the OK button
        $childOKButton = New-Object System.Windows.Forms.Button
        $childOKButton.Location = New-Object System.Drawing.Size(($child_form_width/2 - $standard_button_width - $standard_x_whitespace), $bottom_child_button_baseline)
        $childOKButton.Size = New-Object System.Drawing.Size($standard_button_width, $standard_button_height)
        $childOKButton.Text = "Add to selected"
        $childOKButton.Font = $standard_font
        $childOKButton.Enabled = $false
        $childOKButton.Add_Click({ AddGroups })
        $sonobjForm.Controls.Add($childOKButton)
        
        # creating the Cancel button
        $childCancelButton = New-Object System.Windows.Forms.Button
        $childCancelButton.Location = New-Object System.Drawing.Size(($child_form_width/2 + $standard_x_whitespace), $bottom_child_button_baseline)
        $childCancelButton.Size = New-Object System.Drawing.Size($standard_button_width, $standard_button_height)
        $childCancelButton.Text = "Cancel"
        $childCancelButton.Font = $standard_font
        $childCancelButton.Add_Click({$sonobjForm.Close()})
        $sonobjForm.Controls.Add($childCancelButton)

        $group_finder_textbox = New-Object System.Windows.Forms.TextBox
        $group_finder_button  = New-Object System.Windows.Forms.Button
        $group_finder_listBox = New-Object System.Windows.Forms.ListBox 
        
        Write-Verbose "Creating group finder input box.."
        $group_finder_textbox.DataBindings.DefaultDataSourceUpdateMode = 0
        $group_finder_textbox.Font = New-Object System.Drawing.Font("Lucida Console",8,0,3,0)
        $group_finder_textbox.Location = New-Object System.Drawing.Size($standard_x_whitespace,$standard_y_whitespace)
        $group_finder_textbox.Name = "group_finder_textbox"
        $group_finder_textbox.Size = New-Object System.Drawing.Size(1040,20)
        $group_finder_textbox.Add_KeyDown({if ($_.KeyCode -eq "Enter") { $group_finder_button.PerformClick() }})
        $group_finder_textbox.Font = New-Object System.Drawing.Font("Gill Sans MT",9,1,3,0)
        $sonobjForm.Controls.Add($group_finder_textbox)

        Write-Verbose "Creating group finder SEARCH button.."
        $group_finder_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $group_finder_button.Font = New-Object System.Drawing.Font("Gill Sans MT",9,1,3,0)
        $group_finder_button.Location = New-Object System.Drawing.Size(($standard_x_whitespace*2 + $group_finder_textbox.Size.Width),($standard_y_whitespace - 2))
        $group_finder_button.Name = "group_finder_button"
        $group_finder_button.Size = New-Object System.Drawing.Size(70,23)
        $group_finder_button.Text = "SEARCH"
        $group_finder_button.UseVisualStyleBackColor = $True
        $group_finder_button.add_Click({ if ($group_finder_textbox.Text.Trim() -ne "") {FindGroups $group_finder_textbox.Text.Trim()}  })
        $sonobjForm.Controls.Add($group_finder_button)

        Write-Verbose "Creating group finder results listbox.."
        $group_finder_listBox.Location = New-Object System.Drawing.Size($standard_x_whitespace,($standard_y_whitespace + 25)) 
        $group_finder_listBox.Size = New-Object System.Drawing.Size(($child_form_width - $standard_x_whitespace * 6), 450) 
        $group_finder_listBox.Font = New-Object System.Drawing.Font("Lucida Console",7,0,3,0)
        $group_finder_listBox.SelectionMode = "MultiExtended"
        $group_finder_listBox.Visible = $false
        $sonobjForm.Controls.Add($group_finder_listBox)

        Write-Verbose "Creating progress bar for 'Add to groups' child form.."
        $childProgressBar = New-Object System.Windows.Forms.ProgressBar
        $childProgressBar.DataBindings.DefaultDataSourceUpdateMode = 0
        $childProgressBar.Size = New-Object System.Drawing.Size(($child_form_width/2 - $standard_button_width - $standard_x_whitespace - $standard_x_whitespace*3), $standard_button_height)
        $childProgressBar.Location = New-Object System.Drawing.Size($standard_x_whitespace, $bottom_child_button_baseline)
        $childProgressBar.Name = "childProgressBar"
        $childProgressBar.Style = 1 # blocks (2 = marquee)
        $childProgressBar.Visible = $false
        $sonobjForm.Controls.Add($childProgressBar)

        # creating the "Legend" label
        $legend_label = New-Object System.Windows.Forms.Label
        $legend_label.Location = New-Object System.Drawing.Size(($CancelButton.Location.X + $CancelButton.Size.Width + $standard_x_whitespace * 2), $bottom_button_baseline)
        $legend_label.Size = New-Object System.Drawing.Size(($standard_listbox_width), $standard_label_height) 
        $legend_label.Text = "Legend:  S = Security  D = Distribution"
        $legend_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,0,0)
        $legend_label.AutoSize = $true
        $legend_label.Font = $standard_font
        $SCRIPT:objForm.Controls.Add($legend_label) 

        $mainProgressBar = New-Object System.Windows.Forms.ProgressBar
        $mainProgressBar.DataBindings.DefaultDataSourceUpdateMode = 0
        $mainProgressBar.Size = New-Object System.Drawing.Size(($standard_form_width/2 - $standard_button_width - $standard_x_whitespace - $standard_x_whitespace*3), $standard_button_height)
        $mainProgressBar.Location = New-Object System.Drawing.Size($standard_x_whitespace, $bottom_button_baseline)
        $mainProgressBar.Name = "mainProgressBar"
        $mainProgressBar.Style = 1 # blocks (2 = marquee)
        $mainProgressBar.TabIndex = 2
        $mainProgressBar.Visible = $false
        $SCRIPT:objForm.Controls.Add($mainProgressBar)
    
        # displaying the main form
        Write-Verbose "Displaying the main form.."
        $SCRIPT:objForm.Add_Shown({$SCRIPT:objForm.Activate()})
        [void] $SCRIPT:objForm.ShowDialog()
        
        # returning the selected item(s)
        $SCRIPT:listSelItems
      }
        
    function GetMaxItemLength($array)
      {
        $max = 0
        $array | % { if ($_.length -gt $max) { $max = $_.length } }
        $max
      }

    function AppendSpaces([string]$str, [int]$target)
      {
        for ($i=$str.length;$i -lt $target; $i++) { $str += " " }
        $str
      }
 
    function CleanString([string]$str, [int]$target)
      {
        Write-Debug "Input string length: $($str.length)"
        Write-Debug "Substring start: 0"
        Write-Debug "Substring target: $target"
        $str.Substring(0,$target).Trim()
      }

    $curdomain_completename = (Get-ADDomain -Current LocalComputer | Select DNSRoot).DNSRoot
    Write-Verbose "Working with domain $curdomain_completename"
    Write-Verbose "Checking existence of source entity in AD.."
    $source_user = Get-ADUser $from
    if ($source_user)
      {
        Write-Verbose "Source user found."
      }
    else
      {
        Write-Warning "Source user not found! Exiting!"
        Exit
      }
    
    Write-Verbose "Retrieving groups and other user information..."
    $from_values = Get-ADUser $from -Properties MemberOf | Select -ExpandProperty memberof | Sort | % { Get-ADGroup $_ -Properties * | Select Name, Description, GroupCategory, @{N="ParentOU";E={$a = $_.CanonicalName.split("/"); $a[1..($a.Length-2)] -join '/'}} }
    $max_name_length1 = GetMaxItemLength ($from_values | Select -ExpandProperty Name)
    $new_from_values = $OUs_from = $types_from = @()
    $from_values | % { 
                       if ($_.Description) { $_.Description = " > " + $_.Description }
                       if ($_.name.length -lt $max_name_length1) 
                         { 
                           $new_from_values += ((AppendSpaces -str $_.name -target $max_name_length1) + $_.Description)
                         } 
                       else 
                         { 
                           $new_from_values += ($_.name + $_.Description) 
                         }
                     }
    $from_values | % { $OUs_from += $_.ParentOU }
    $from_values | % { $types_from += $_.GroupCategory }
    $from_name = Get-ADUser $from | Select -ExpandProperty Name
    $description1 = "[SOURCE] These are the groups ($($from_values.count) total) of user $($from) ($($from_name)):"
    if ($new_from_values.count -eq 0) { $new_from_values += "<no groups (excluding default groups such as Domain Users)>"; $OUs_from += "<no groups>"; $types_from += "<no groups>";  }

    $selItems = SelectionBox $from $new_from_values $description1
  }

function AD-GetUserStatus
  {
    <# .SYNOPSIS
       This function interrogates Active Directory (current domain) and displays information on the status of the specified domain account.

       .EXAMPLE
       AD-GetUserStatus TestUser
    #>

    [cmdletbinding()] param([parameter(Mandatory=$true)] $Account)

    Get-ADUser -Identity $Account -Properties LockedOut,PasswordExpired | Select Name,Enabled,LockedOut,PasswordExpired | FT -Auto
  }

function AD-GetComputerSessions
  {
    <# .SYNOPSIS
       Retrieves user sessions on a local or remote Windows machine and returns an array of objects, one for each session.
       The hostname of the remote machine can be explicitly specified through the -ComputerName parameter; if nothing is specified, it will work with localhost.

       .EXAMPLE
       AD-GetComputerSessions -ComputerName server1
    #>

    [cmdletbinding()] param([string] $ComputerName = "localhost")
    
    $output = quser /SERVER:$ComputerName

    <# quser example output:
    
    C:\>quser /SERVER:server1
    USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
    user1                 rdp-tcp#2           1  Active       1:39  22/03/2016 12:35
    user2                 rdp-tcp#1           2  Active          .  23/03/2016 11:04
    
    #>

    $lines = $output -split "`n"
    $remotesessions = @()
    
    ForEach ($line in $lines[1..($lines.count-1)]) # line zero contains only column names
      {
        Write-Verbose "Working with line: $line ($($line.length) characters)"
        $values = @()
        $values += $line.Substring(0,23).Trim()  # USERNAME
        $values += $line.Substring(23,19).Trim() # SESSIONNAME
        $values += $line.Substring(43,3).Trim()  # ID
        $values += $line.Substring(46,7).Trim()  # STATE
        $values += $line.Substring(55,10).Trim() # IDLE TIME
        $values += $line.Substring(65).Trim()    # LOGON TIME
        Write-Verbose "Created values array with $($values.Count) elements: $($values -join ";")"

        $remotesession = New-Object PSCustomObject -Property @{UserName = $values[0]; SessionName = $values[1]; ID = $values[2]; State = $values[3]; IdleTime = $values[4]; LogonTime = $values[5];}
        $remotesessions += $remotesession
      }
    $remotesessions
  }

### VMware functions ###

function VMw-ConnectToDefaultVC
  {
    <# .SYNOPSIS
       VMware-specific function that opens a connection to the default vCenter Server as specified in module Bitman.psm1
       The function will attempt Kerberos authentication using the credentials of the current user.

       .EXAMPLE
       VMw-ConnectToDefaultVC
    #>
        
    Connect-VIServer $SCRIPT:default_vcenter_server -WarningAction SilentlyContinue
    Write-Host "`n"
  }

function VMw-FindVMsWithReservations
  {
    <# .SYNOPSIS
       VMware-specific function that opens a connection to the default vCenter Server (as specified in Bitman.psm1) and lists all VMs with a reservation (CPU, memory or both)

       .EXAMPLE
       VMw-FindVMsWithReservations
    #>

    [cmdletbinding()] param()

    Write-Verbose "Connecting to default vCenter server ($SCRIPT:default_vcenter_server)..."
    VMw-ConnectToDefaultVC
    Write-Host "Getting all the VMs and filtering on those with reservations..."
    $VMs = Get-VM | ? {$_.ExtensionData.ResourceConfig.MemoryAllocation.Reservation -ne "0" -or $_.ExtensionData.ResourceConfig.CpuAllocation.Reservation -ne "0"}
    Write-Verbose "Reading information..."
    if ($VMs)
      {
        ForEach ($VM in $VMs)
          { 
            "" | Select @{N="Name";E={$VM.Name}},
            @{N="CPU Reservation";E={$VM.ExtensionData.ResourceConfig.CpuAllocation.Reservation}},
            @{N="Memory Reservation";E={$VM.ExtensionData.ResourceConfig.MemoryAllocation.Reservation}} 
          }
      }
    Write-Host "Done."
  }

function VMw-FindVMsWithSnapshots
  {
    <# .SYNOPSIS
       VMware-specific function that opens a connection to the default vCenter Server (as specified in Bitman.psm1) and lists all VMs with one or more snapshots.

       .EXAMPLE
       VMw-FindVMsWithSnapshots
    #>

    [cmdletbinding()] param()

    Write-Verbose "Connecting to default vCenter server ($SCRIPT:default_vcenter_server)..."
    VMw-ConnectToDefaultVC
    Write-Host "Retrieving VMs with snapshots..."
    Get-View -ViewType VirtualMachine -Property Name,Snapshot -Filter @{"Snapshot"="VMware.Vim.VirtualMachineSnapshotInfo"} | Select Name
    Write-Host "Done."
  }

function VMw-GetVMPath
  {
    <# .SYNOPSIS
       VMware-specific function that finds where a given VM is located in a vSphere virtual environment; 
       Connects to the default vCenter Server (as specified in Bitman.psm1), which must be up & running

       .EXAMPLE
       VMw-GetVMPath server1
    #>

    [cmdletbinding()] param([parameter(Mandatory=$true)] [string]$VMname)

    Write-Verbose "Connecting to default vCenter server ($SCRIPT:default_vcenter_server)..."
    VMw-ConnectToDefaultVC
    Write-Verbose "Getting the VM..."
    $vm = Get-VM $VMname
    $path = ""
    if ($VM)
      {
        Write-Verbose "VM found, getting information..."
        $vmhost = $vm.VMHost.Name
        $vmcluster = (Get-Cluster -VMHost $vmhost).Name
        $dc = (Get-Datacenter -VMHost $vmhost).Name
        $path = "Datacenter " + $dc + " -> Cluster " + $vmcluster+ " -> Host " + $vmhost + " -> VM " + $VMname + "`n(folder: $($vm.Folder.Name))"
      }
    else
      {
        Write-Host "Failed to get the VM; see errors above."
      }
    $path
  }

function VMw-GetVMCustomAttributes+Annotations
  {
    <# .SYNOPSIS
       VMware-specific function that gets all custom attributes of a given VM and returns them wrapped in a PSCustomObject.
       The function automatically connects to the default vCenter Server (as specified in Bitman.psm1), which must be up & running.

       .EXAMPLE
       VMw-GetVMCustomAttributes+Annotations server1
    #>
    
    [cmdletbinding()] param([parameter(Mandatory=$true)] [string]$VMname)
    
    Write-Verbose "Connecting to default vCenter server ($SCRIPT:default_vcenter_server)..."
    VMw-ConnectToDefaultVC
    Write-Verbose "Getting the VM..."
    $VM = Get-View -ViewType VirtualMachine -Filter @{'name'=$VMname}
    $custom_attributes = @()
    if ($VM)
      {
        Write-Verbose "VM found, starting data collection.."
        $customvalues = $VM.summary.customvalue | Select Value,Key
        $customfields = $VM.AvailableField | Select Name,Key
        $object = New-Object PSCustomObject
        ForEach ($r in $customfields)
          {
            $f = ""
            ForEach ($r2 in $customvalues) { if ($r.Key -eq $r2.Key) { $f = $r2.Value } }
            $object | Add-Member -type NoteProperty -Name $r.name -Value $f
          }
        $annotations = ($VM.summary.config.annotation -replace "`n", "; ")
        $object | Add-Member -type NoteProperty -Name Annotations -Value $annotations
        $custom_attributes += $object
      }
    $custom_attributes
  }

function VMw-TakeWSUSSnapshots
  {
    <# .SYNOPSIS
       VMware-specific function that connects to the default vCenter Server (as specified in Bitman.psm1) and takes snapshots for one or more VMs.
       VMs must be specified through an array of strings (their names).
       All snapshot will be named with the following nomenclature: [DD.MM.YYYY] Pre-WSUS

       .EXAMPLE
       Get-Content C:\vms.txt | VMw-TakeWSUSSnapshots
    #>

    [cmdletbinding()] param([parameter(Mandatory=$true)] $VMs)
    
    if (($VMs | Measure).Count -gt 0)
      {
        Write-Verbose "Connecting to default vCenter server ($SCRIPT:default_vcenter_server)..."
        VMw-ConnectToDefaultVC
        $today = (get-date).toShortDateString() -replace "/", "."
        Write-Host "Taking snapshots..."
        $VMs | % { Write-Verbose "Snapshotting $_"; New-Snapshot -VM $_.Trim() -Name "[$today] Pre-WSUS" -Memory:$false -Quiesce:$false }
        Write-Host "Done (hopefully without errors)."
      }
  }

function VMw-TakeSnapshots
  {
    <# .SYNOPSIS
       VMware-specific function that connects to the default vCenter Server (as specified in Bitman.psm1) and takes snapshots for one or more VMs.
       VMs must be specified through an array of strings (their names).
       All snapshot will be named with the following nomenclature: [DD.MM.YYYY] PowerShell_snapshot
       The user can specify an alternate final part, but the date enclosed in square brackets will always be prefixed.

       .EXAMPLE
       Get-Content C:\vms.txt | VMw-TakeSnapshots
    #>

    [cmdletbinding()] param([parameter(Mandatory=$true)] $VMs, [string]$name="PowerShell_snapshot")
    
    if (($VMs | Measure).Count -gt 0)
      {
        Write-Verbose "Connecting to default vCenter server ($SCRIPT:default_vcenter_server)..."
        VMw-ConnectToDefaultVC
        $today = (get-date).toShortDateString() -replace "/", "."
        Write-Host "Taking snapshots..."
        $VMs | % { Write-Verbose "Snapshotting $_"; New-Snapshot -VM $_.trim() -Name "[$today] $name" -Memory:$false -Quiesce:$false }
        Write-Host "Done (hopefully without errors)."
      }
  }

function VMw-RemoveAllSnapshots
  {
    <# .SYNOPSIS
       VMware-specific function that connects to the default vCenter Server (as specified in Bitman.psm1) and removes all snapshots for one or more VMs.
       VMs must be specified through an array of strings (their names).

       .EXAMPLE
       Get-Content C:\vms.txt | VMw-RemoveAllSnapshots
    #>

    [cmdletbinding()] param([parameter(Mandatory=$true)] $VMs)
    
    if (($VMs | Measure).Count -gt 0)
      {
        Write-Verbose "Connecting to default vCenter server ($SCRIPT:default_vcenter_server)..."
        VMw-ConnectToDefaultVC
        Write-Host "Removing all snapshots of the specified VMs..."
        $VMs | % { Write-Verbose "Working with $_"; Get-Snapshot $_ | Remove-Snapshot -confirm:$false }
        Write-Host "Done (hopefully without errors)."
      }
  }

function VMw-RemoveWSUSSnapshots
  {
    <# .SYNOPSIS
       VMware-specific function that connects to the default vCenter Server (as specified in Bitman.psm1) and removes all WSUS snapshots for one or more VMs.
       VMs must be specified through an array of strings (their names).
       WSUS snapshots are identified through the presence of "WSUS" in their names.

       .EXAMPLE
       Get-Content C:\vms.txt | VMw-RemoveWSUSSnapshots
    #>
    
    [cmdletbinding()] param([parameter(Mandatory=$true)] $VMs)
    
    if (($VMs | Measure).Count -gt 0)
      {
        Write-Verbose "Connecting to default vCenter server ($SCRIPT:default_vcenter_server)..."
        VMw-ConnectToDefaultVC
        Write-Verbose "Removing WSUS snapshots..."
        $VMs | % { Write-Verbose "Working with $_"; Get-Snapshot $_ | Where {$_.Name -match "WSUS"} | Remove-Snapshot -confirm:$false }
        Write-Host "Done (hopefully without errors)."
      }
  }

function VMw-GetVMRDMInfo
  {
    <# .SYNOPSIS
       VMware-specific function that connects to the default vCenter Server (as specified in Bitman.psm1) and retrieves information about the RDM disks of a given VM.
       The VM can be specified through a string containing the name or a VM object (Get-VM).

       .EXAMPLE
       VMw-GetVMRDMInfo server1

       .EXAMPLE
       VMw-GetVMRDMInfo (Get-VM server1)
    #>

    [cmdletbinding()] param([parameter(Mandatory=$true)] [string]$VM)

    Write-Verbose "Connecting to default vCenter server ($SCRIPT:default_vcenter_server)..."
    VMw-ConnectToDefaultVC

    if (Get-VM $VM)
      {
        Write-Verbose "VM found, getting disks..."
        $Disks = Get-VM $VM | Get-HardDisk | Where {$_.DiskType -eq “RawPhysical”}
        Write-Verbose "Found $($Disks.count) raw devices; getting information..."
        Foreach ($Disk in $Disks)
          {
            Write-Host "VMDK file: $($Disk.Filename)"
            Write-Host "SCSI canonical name: $($Disk.SCSICanonicalName)"
            $Lun = Get-SCSILun $Disk.SCSICanonicalName -VMHost (Get-VM $VM).VMHost
            Write-Host "Runtime name: $($Lun.RuntimeName)"
            Write-Host "LUN ID: $($Lun.RuntimeName.Substring($Lun.RuntimeName.LastIndexof(“L”)+1))"
            Write-Host "Capacity (GB): $($Lun.CapacityGB)"
            Write-Host "`n"
          }
        Write-Host "Done (hopefully without errors)."
      }
    else
      {
        Write-Warning "I was unable to get the VM!"
      }
  }

### Exchange functions ###

function Exch7-GetDLSendAsPermissions
  {
    <# .SYNOPSIS
       Exchange-specific function that connects to the current domain's Exchange environment and extracts the SendAs permissions of a mailbox.
       Information does not include inherited permissions, such as NT AUTHORITY\SELF.
       Developed and tested against Exchange 2007, the function will quit if the version is different.
       The Identity parameter specifies the group that you want to modify. You can use any value that uniquely identifies the group, for example:
       Name
       Display name
       Alias
       Distinguished name (DN)
       Canonical DN
       Email address
       GUID

       .EXAMPLE
       Exch7-GetDLSendAsPermissions -Identity TestDL
    #>

    [cmdletbinding()] param([parameter(Mandatory=$true)] [string]$identity)
    
    $group = Get-DistributionGroup $identity
    $ver = $group.ExchangeVersion.ExchangeBuild.Major # 8 = Exchange 2007, 15 = Exchange 2013, etc
    if ($group)
      {
        if ($ver -eq 8)
          {
            Get-ADPermission -Identity $group.name | ? {($_.ExtendedRights -like “*Send-As*”) -and ($_.IsInherited -eq $false) -and -not ($_.User -like “NT AUTHORITY\SELF”)} | Select User | Sort User
          }
        else
          {
            Write-Warning "Sorry, this group does not appear to be on Exchange 2007."
          }
      }
    else
      {
        Write-Warning "Sorry, I was unable to find the corresponding group!"
      }
  }

function Exch7-GetMailboxStatus
  {
    <# .SYNOPSIS
       Exchange-specific function that connects to the current domain's Exchange environment and extracts the most important statistics of a mailbox.
       Information includes display name, last logon time, current storage usage and storage quotas.
       Developed and tested against Exchange 2007, the function will quit if the version is different.

       .EXAMPLE
       Exch7-GetMailboxStatus TestUser
    #>

    [cmdletbinding()] param([parameter(Mandatory=$true)] [string]$account)
    
    Write-Verbose "Searching for the corresponding mailbox.."
    $mbx = Get-Mailbox $account 
    $ver = $mbx.ExchangeVersion.ExchangeBuild.Major # 8 = Exchange 2007, 15 = Exchange 2013, etc
    if ($mbx)
      {
        if ($ver -eq 8)
          {
            Write-Verbose "Getting mailbox information.."
            $mbx = Get-MailboxStatistics $account
            $mbx | Select DisplayName, LastLogonTime, @{N="Emails";E={$_.ItemCount}}, @{N="Size (MB)";E={$_.TotalItemSize.value.ToMB()}}, StorageLimitStatus | FT -auto
            $mbx = Get-Mailbox $account 
            $notes = "Notes: N/A `n"
            Write-Verbose "Getting storage statistics.."
            if ($mbx.UseDatabaseQuotaDefaults) 
              {
                $DB = Get-MailboxDatabase $mbx.Database
                if ($DB.issuewarningquota.IsUnlimited) { $quota1 = "unlimited" } else { $quota1 = $DB.issuewarningquota.value.ToMB() }
                if ($DB.prohibitsendquota.IsUnlimited) { $quota2 = "unlimited" } else { $quota2 = $DB.prohibitsendquota.value.ToMB() }
                if ($DB.prohibitsendreceivequota.IsUnlimited) { $quota3 = "unlimited" } else { $quota3 = $DB.prohibitsendreceivequota.value.ToMB() }
                $notes = "Notes: This mailbox uses the default database storage quotas. `n"
              }
            else
              {
                if ($mbx.issuewarningquota.IsUnlimited) { $quota1 = "unlimited" } else { $quota1 = $mbx.issuewarningquota.value.ToMB() }
                if ($mbx.prohibitsendquota.IsUnlimited) { $quota2 = "unlimited" } else { $quota2 = $mbx.prohibitsendquota.value.ToMB() }
                if ($mbx.prohibitsendreceivequota.IsUnlimited) { $quota3 = "unlimited" } else { $quota3 = $mbx.prohibitsendreceivequota.value.ToMB() }
              }
            $mbx | Select @{N="Type";E={$_.recipienttype}}, @{N="Warning quota (MB)";E={$quota1}}, @{N="Prohibit send quota (MB)";E={$quota2}}, @{N="Prohibit send/receive quota (MB)";E={$quota3}} | FT -auto
            Write-Host $notes
          }
        else
          {
            Write-Warning "Sorry, this mailbox does not appear to be on Exchange 2007."
          }
      }
    else
      {
        Write-Warning "Sorry, I was unable to find the corresponding mailbox!"
      }
  }

function Exch7-IncreaseMailboxStorage
  {
    <# .SYNOPSIS
       Exchange-specific function that connects to the current domain's Exchange environment and increases the storage quotas of a mailbox.
       Developed and tested against Exchange 2007, the function will quit if the version is different.

       .EXAMPLE
       Exch7-IncreaseMailboxStorage TestUser 100MB
    #>

    [cmdletbinding()] param([parameter(Mandatory=$true)] $account, [parameter(Mandatory=$true)] $value)
    
    Write-Verbose "Searching for the corresponding mailbox.."
    $mbx = Get-Mailbox $account
    $ver = $mbx.ExchangeVersion.ExchangeBuild.Major # 8 = Exchange 2007, 15 = Exchange 2013, etc
    if ($mbx)
      {
        if ($ver -eq 8)
          {
            $Warn = "$($mbx.issuewarningquota+$value)"
            $Send = "$($mbx.ProhibitSendQuota+$value)"
            $SendReceive = "$($mbx.ProhibitSendReceiveQuota+$value)"
            Set-Mailbox -Identity $account -IssueWarningQuota $Warn -ProhibitSendQuota $Send -ProhibitSendReceiveQuota $SendReceive -UseDatabaseQuotaDefaults $false
            Write-Host "Done (hopefully without errors)."
          }
        else
          {
            Write-Warning "Sorry, this mailbox does not appear to be on Exchange 2007."
          }
      }
    else
      {
        Write-Warning "Sorry, I was unable to find the corresponding mailbox!"
      }
  }

function Exch7-ConvertDLToMailbox
  {
    <# .SYNOPSIS
       Exchange-specific function that connects to the current domain's Exchange environment and converts a distribution list to a true shared mailbox.
       The function will copy permissions and addresses, plus it will rename the DL and use it to forward emails to all users.
       Developed and tested against Exchange 2007, the function will quit if the version is different.

       .EXAMPLE
       Exch7-ConvertDLToMailbox TestDL
    #>

    [cmdletbinding()] param([parameter(Mandatory=$true)] [string]$name, [switch]$NoForward)
     
    Write-Verbose "Searching for the distribution list.."
    $DL = Get-DistributionGroup $name
    $ver = $DL.ExchangeVersion.ExchangeBuild.Major # 8 = Exchange 2007, 15 = Exchange 2013, etc
    $oldDL = Get-DistributionGroup $name

    if ($DL)
      {
        if ($ver -eq 8)
          {
            # Retrieving primary SMTP address and membership
            Write-Verbose "Retrieving primary SMTP address and membership.."
            $addr = $DL.PrimarySmtpAddress.ToString()
            $members = Get-DistributionGroupMember $DL
        
            # Retrieving the DL's LegacyExchangeDN; the cache in Outlook and in OWA uses the value of this attribute to route emails internally
            # If the value changes, the delivery of email messages may fail with a 5.1.1 NDR.
            Write-Verbose "Retrieving the DL's LegacyExchangeDN.."
            $LegacyExchangeDN = $DL.LegacyExchangeDN
    
            # get permissions: I only need to check sendAs, all members will need to have full access
            Write-Verbose "Retrieving the DL's permissions.."
            $perms = Get-ADPermission -Identity $name | Where {($_.ExtendedRights -like “*Send-As*”) -and ($_.IsInherited -eq $false) -and ($_.User -notlike "*NT AUTHORITY*")}
        
            # I will create the mailbox on the mos "generic" database, because I have no easy way of determining which is best
            $db = "xpexcmailprd\UserRestanti"
    
            <# I rename DL to "Notify xxx" as well as its email addresses BEFORE creating mbx
               I can't create the mailbox if an object with the same name already exists in AD
               To properly rename a distribution group, you need to not only change the name of the group, 
               but also the Alias, DisplayName and entries in the EmailAddresses field. 
               I also need to rename the AD distr. group, which is a linked but separate entity #>
            Write-Verbose "Renaming the DL (adding prefix 'Notify.').."
            $newname = "Notify." + $name
            $adgroup = Get-ADGroup $name
            Set-ADGroup $adgroup -SamAccountName $newname
            Rename-ADObject $adgroup -NewName $newname
            Set-DistributionGroup $name -alias $newname -DisplayName $newname
            
            # to rename all addresses, I actually clone them to a temp var, delete them, then add them back with the new names
            Write-Verbose "Renaming the email addresses of the DL (adding prefix 'Notify.').."
            $curaddresses = $DL.EmailAddresses.Clone()
            $DL.EmailAddresses.Clear()
            For ($i = ($curaddresses.count-1); $i -ge 0; $i--)
              {
                $DL.EmailAddresses.Add("Notify." + $curaddresses[$i].AddressString.ToString())
              }
            $DL | Set-DistributionGroup
    
            # resetting the primary address with the new name
            Write-Verbose "Resetting the primary address of the DL.."
            Set-DistributionGroup $DL -PrimarySmtpAddress ("Notify." + $addr)
    
            # I make the DL "hidden"
            Write-Verbose "Hiding the DL.."
            $DL.HiddenFromAddressListsEnabled = "true"
            $DL | Set-DistributionGroup
    
            # now that the DL has been renamed, I can create a mailbox with the old name of the DL; I wait a few secs for DB updates
            Write-Verbose "Waiting 10 seconds for the changes to take effect.."
            Start-Sleep 10
            Write-Verbose "Creating the new shared mailbox.."
            $mbx = New-Mailbox -Shared -Name $name -DisplayName $name -Alias ($name -replace '\s','') -UserPrincipalName $addr -Database $db
            
            # now I proceed with adding the email addresses of the old DL
            Write-Verbose "Adding the email addresses of the old DL to the mailbox.."
            For ($i = ($curaddresses.count-1); $i -ge 0; $i--)
              {
                $mbx.EmailAddresses.Add($curaddresses[$i].AddressString.ToString())
              }
            $mbx | Set-Mailbox
            
            # I disable email address policies, authentication, then I setup the primary address and forwarding to the old, renamed DL
            Write-Verbose "Disabling email address policies, authentication.."
            Set-Mailbox $mbx -EmailAddressPolicyEnabled $false -RequireSenderAuthenticationEnabled $false -PrimarySmtpAddress $addr
            Write-Verbose "Setting up the primary address and forwarding to the old, renamed DL.."
            if (-not $NoForward)
              {
                Set-Mailbox $mbx -DeliverToMailboxAndForward $true -ForwardingAddress ("Notify." + $addr) 
              }
    
            # I add the DG’s legacyExchangeDN as an X500 address to the new mailbox
            Write-Verbose "Adding the DL’s legacyExchangeDN as an X500 address to the new mailbox.."
            $completeDN = "X500:"+$LegacyExchangeDN
            $mbx.EmailAddresses.Add($completeDN)
            $mbx | Set-Mailbox
    
            # I set full access and send as permissions; the $perms array only contains SendAs permissions
            Write-Verbose "Setting permissions.."
            if ($perms.count -gt 0) 
              { 
                $perms | % { Add-MailboxPermission -Identity $name -User $_.User -AccessRights SendAs -InheritanceType All }
                  }
            if ($members.count -gt 0) 
              { 
                $members | % { Add-MailboxPermission -Identity $name -User $_.Identity -AccessRights FullAccess -InheritanceType All } 
              }
    
            # I set all custom attributes
            Write-Verbose "Setting custom attributes.."
            Set-Mailbox $mbx -CustomAttribute1 $DL.CustomAttribute1 `
                             -CustomAttribute2 $DL.CustomAttribute2 `
                             -CustomAttribute3 $DL.CustomAttribute3 `
                             -CustomAttribute4 $DL.CustomAttribute4 `
                             -CustomAttribute5 $DL.CustomAttribute5 `
                             -CustomAttribute6 $DL.CustomAttribute6 `
                             -CustomAttribute7 $DL.CustomAttribute7 `
                             -CustomAttribute8 $DL.CustomAttribute8 `
                             -CustomAttribute9 $DL.CustomAttribute9 `
                             -CustomAttribute10 $DL.CustomAttribute10 `
                             -CustomAttribute11 $DL.CustomAttribute11 `
                             -CustomAttribute12 $DL.CustomAttribute12 `
                             -CustomAttribute13 $DL.CustomAttribute13 `
                             -CustomAttribute14 $DL.CustomAttribute14 `
                             -CustomAttribute15 $DL.CustomAttribute15
            Write-Verbose "Done (hopefully without errors)!"
          }
        else
          {
            Write-Warning "Sorry, this DL does not appear to be on Exchange 2007."
          }
      }
    else
      {
        Write-Warning "Sorry, I was unable to find the DL. I have nothing to work with."
      }
  }

function Exch7-AuthorizeAnonSMTPSend
  {
    <# .SYNOPSIS
       Exchange-specific function that connects to the current domain's Exchange environment and authorizes a given IP address of a server to send email 
       without authentication via the transport servers of Exchange. Developed and tested against Exchange 2007, the function will NOT quit if the version is different.
       NOTE: because some organizations have mixed Exchange environments (example: 2007 + 2013), this function will not just authorize the IP on all servers it finds,
             but only on those specified in Bitman.psm1 ($SCRIPT:default_exch7_transport_servers)

       .EXAMPLE
       Exch7-AuthorizeAnonSMTPSend 127.0.0.1
    #>
    
    [cmdletbinding()] param([parameter(Mandatory=$true)] $IP)

    Write-Verbose "Retrieving list of hub transport servers.."
    
    $hubservers = Get-TransportServer | Where { $_.Name -like $SCRIPT:default_exch7_transport_servers }
    Foreach ($s in $hubservers)
      {
        Write-Verbose "Reconfiguring connectors on server $($s.name).."
        $id = "$($s.name)\smtpService"
        $connector = Get-ReceiveConnector -Identity $id
        $connector.RemoteIPRanges += $IP
        Set-ReceiveConnector -Identity $id -RemoteIPRanges $connector.RemoteIPRanges
      }
    Write-Verbose "Command completed on $($hubservers.count) hub servers."
    Write-Host "Done (hopefully without errors)!"
  }

function Exch7-GetPublicFoldersByUser
  {
    <# .SYNOPSIS
       Exchange-specific function that connects to the current domain's Exchange environment and lists all the public folders that a domain user has access to, and the permissions for each folder.
       Developed and tested against Exchange 2007, the function will NOT quit if the version is different.

       .EXAMPLE
       Get-PublicFolderByUser TestUser
    #>
    
    [cmdletbinding()] param([parameter(Mandatory=$true)] $User)
    
    # I prepare an array with all the public folders
    Write-Verbose "Collecting Public Folders..."
    $PublicFolders = Get-PublicFolder -Recurse
    
    # I check AD and retrieve the canonical name for the user
    Write-Verbose "Getting user CN for $User"
    $User = Get-ADUser $User -Properties CanonicalName | Select -ExpandProperty CanonicalName

    # I iterate through all the public folders and find the folders for which the user has permissions
    if ($user)
      {
        $final_permissions = @()

        "Sifting through the public folders looking for user {0}..." -f $User.split("/")[-1]
        Foreach ($f in $PublicFolders)
          {
            $p = Get-PublicFolderClientPermission -Identity $f.EntryId | ? { $_.User -match $User } 
            if ($p) { $final_permissions += $p }
          }
        Write-Verbose "Done (hopefully without errors)!`n"
        $final_permissions | Select Identity, AccessRights | FL
      }
  }

function Exch7-AddOwnerToDL
  {
    <# .SYNOPSIS
       Exchange-specific function that connects to the current domain's Exchange environment and adds an aditional owner ("owner") to a DL.
       Technically there is only one manager for a given DL but multiple people can have write permissions for the membership property.
       Developed and tested against Exchange 2007, the function will quit if the version is different.

       .EXAMPLE
       Exch7-AddOwnerToDL testDL TestUser
    #>

    [cmdletbinding()] param([parameter(Mandatory=$true)] [string]$name, [parameter(Mandatory=$true)] [string]$user)

    $DL = Get-DistributionGroup $name
    $ver = $DL.ExchangeVersion.ExchangeBuild.Major # 8 = Exchange 2007, 15 = Exchange 2013, etc

    if ($DL)
      {
        if ($ver -eq 8) { Get-DistributionGroup $name | Add-ADPermission -User $User -AccessRights WriteProperty -Properties "Member" }
        else { Write-Warning "Sorry, this mailbox does not appear to be on Exchange 2007." }
      }
  }

function Exch7-MonthlyEmails
  {
    <# .SYNOPSIS
       Exchange-specific function that connects to the current domain's Exchange environment and displays a couple of simple statistics about an email address: 
       the number of sent and received emails in a month. The function interrogates all transport server it finds.
       Developed and tested against Exchange 2007 and 2013, the function will NOT quit if the version is different.

       .EXAMPLE
       Exch7-MonthlyEmails necromancer@crypt.com
    #>

    [cmdletbinding()] param([parameter(Mandatory=$true)] [string]$address)
    
    Write-Warning "`nIMPORTANT: if your Exchange env is mixed (for instance 2007 + 2013), this function must be ran in the most recent environment; if not, results could be inconsistent."
    $sender = $recipient = $address
    $start = “03/30/2016”  # MM/DD/YYYY - this format must be changed if OS regional settings are non-US
    $end = “04/01/2016”    # MM/DD/YYYY - this format must be changed if OS regional settings are non-US
    $receive_events = "RECEIVE"
    $send_events = "SEND|DELIVER" # send = destinatari esterni, deliver = interni
    Write-Verbose "Retrieving transport servers.."
    $servers = Get-TransportServer
    Write-Verbose "Searching.."
    $R1 = $servers | Get-MessageTrackingLog -ResultSize Unlimited -Start $start -End $end -Sender $sender | ? { $_.EventID -match $send_events } | Sort -Property MessageID -Unique
    $R2 = $servers | Get-MessageTrackingLog -ResultSize Unlimited -Start $start -End $end -Recipients $recipient | ? { $_.EventID -match $receive_events } | Sort -Property MessageID -Unique
    Write-Host "Address: $address -> Sent: $($R1.Count), received: $($R2.count); messages were counted based on unique message IDs.`n"
  }

function Exch7-CreateContacts
  {
    <# .SYNOPSIS
       Exchange-specific function that connects to the current domain's Exchange environment and takes an array of SMTP address, then creates a contact for each address.
       For each object, it creates a new mail contact object in the Microsoft Active Directory and then mail-enables the mail contact.
       The contacts are created in the default organizational unit as specified in Bitman.psm1 ($SCRIPT:default_contacts_OU).
       Developed and tested against Exchange 2007, the function will NOT quit if the version is different.

       .EXAMPLE
       Exch7-CreateContacts "a@b.com","c@d.com"
    #>

    [cmdletbinding()] param([parameter(Mandatory=$true)] [array]$addresses)
    
    if ($addresses)
      {
        ForEach ($address in $addresses)
          {
            Write-Host "Creating contacts in domain $curdomain under OU $SCRIPT:default_contacts_OU"
            $name = ($address -split '@')[0] -replace '\.',' '
            Write-Verbose "Creating contact with name '$name' and address '$address'"
            New-MailContact -Name $name -ExternalEmailAddress $address -OrganizationalUnit $SCRIPT:default_contacts_OU
            Write-Host "Done (hopefully without errors)."
          }
      }
  }

### GUI functions ###

function UI-SimpleChildForm
  {
    param($content)
    
    $child_form = New-Object System.Windows.Forms.Form
    $child_form_width = 980
    $child_form_height = 484
    $content_textbox = New-Object System.Windows.Forms.TextBox
    $InitialFormWindowState = New-Object System.Windows.Forms.FormWindowState

    $child_form_onload = { 
                           $content_textbox.Text = $content
                           $content_textbox.SelectionStart = 1
                           $content_textbox.SelectionLength = 0
                           $child_form.WindowState = $InitialFormWindowState
                         }

    $child_form.BackColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
    $child_form.ClientSize = New-Object System.Drawing.Size($child_form_width,$child_form_height)
    $child_form.DataBindings.DefaultDataSourceUpdateMode = 0
    $child_form.FormBorderStyle = 5
    $child_form.Name = "child_form"
    $child_form.StartPosition = 4
    $child_form.Text = "Details"
    $child_form.TopMost = $True
    $child_form.add_Load($child_form_onload)

    $content_textbox.DataBindings.DefaultDataSourceUpdateMode = 0
    $content_textbox.Location = New-Object System.Drawing.Point(12,11)
    $content_textbox.Multiline = $True
    $content_textbox.Name = "content_textbox"
    $content_textbox.Size = New-Object System.Drawing.Size(($child_form_width - 22),($child_form_height - 24))
    $content_textbox.TabIndex = 0
    $content_textbox.ReadOnly = $True
    $content_textbox.ScrollBars = "Vertical"
    $content_textbox.Font = New-Object System.Drawing.Font("Lucida Console",8.25,0,3,0)
    $child_form.Controls.Add($content_textbox)

    $InitialFormWindowState = $child_form.WindowState 
    $child_form.ShowDialog()| Out-Null
  }

function UI-SelectionBox
  {
    <# .SYNOPSIS
       Creates a graphical selection box and returns the selection (or null).
       User must pass the items via an array of strings. A description can also be specified, but that is optional.

       .EXAMPLE
       $items = "a", "b", "c"
       $selection = UI-SelectionBox $items "Please select a letter:"
       $selection
    #>

    param([parameter(Mandatory=$true)] [array]$items, [string]$description = "Please select:")

    $SCRIPT:listSelItems = @()
    
    # loading .NET framework classes
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 

    # setting a few "standard" parameters
    $SCRIPT:objForm = New-Object System.Windows.Forms.Form 
    $SCRIPT:objForm.Size = New-Object System.Drawing.Size(900,500)
    $SCRIPT:objForm.StartPosition = "CenterScreen"
    $SCRIPT:objForm.Topmost = $True
    $SCRIPT:objForm.KeyPreview = $True
    $SCRIPT:objForm.Add_KeyDown({ if ($_.KeyCode -eq "Enter") {$objListbox.SelectedItems | % {$SCRIPT:listSelItems += $_}; $SCRIPT:objForm.Close()}})
    $SCRIPT:objForm.Add_KeyDown({if ($_.KeyCode -eq "Escape") {$SCRIPT:objForm.Close()}})
    
    # setting variable parameters for the form
    $SCRIPT:objForm.Text = "Make a selection"
    
    # creating the OK button
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Size(375,430)
    $OKButton.Size = New-Object System.Drawing.Size(75,23)
    $OKButton.Text = "OK"
    $OKButton.Add_Click({$objListbox.SelectedItems | % {$SCRIPT:listSelItems += $_}; $SCRIPT:objForm.Close()})
    $SCRIPT:objForm.Controls.Add($OKButton)
    
    # creating the Cancel button
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Size(450,430)
    $CancelButton.Size = New-Object System.Drawing.Size(75,23)
    $CancelButton.Text = "Cancel"
    $CancelButton.Add_Click({$SCRIPT:objForm.Close()})
    $SCRIPT:objForm.Controls.Add($CancelButton)
    
    # creating a label for the list
    $objLabel = New-Object System.Windows.Forms.Label
    $objLabel.Location = New-Object System.Drawing.Size(10,5) 
    $objLabel.Size = New-Object System.Drawing.Size(500,20) 
    $objLabel.Text = $description
    $SCRIPT:objForm.Controls.Add($objLabel) 
    
    # creating the list box and adding it to the form
    $objListBox = New-Object System.Windows.Forms.ListBox 
    $objListBox.Location = New-Object System.Drawing.Size(10,25) 
    $objListBox.Size = New-Object System.Drawing.Size(865,235) 
    $objListBox.Font = "Lucida Console,7"
    
    $objListbox.SelectionMode = "MultiExtended"
    $items | % { [void] $objListBox.Items.Add($_) }
    $SCRIPT:objForm.Controls.Add($objListBox) 

    # displaying the selection box
    $SCRIPT:objForm.Add_Shown({$SCRIPT:objForm.Activate()})
    [void] $SCRIPT:objForm.ShowDialog()
    
    # returning the select item
    $SCRIPT:listSelItems
  }

function UI-MessageBox
  {
    <# .SYNOPSIS
       Displays a graphical pop-up with an informationl message.

       .EXAMPLE
       UI-MessageBox "Please take note of this message."
    #>

    param([string]$message="At this point I wanted to notify you of something, but I forgot to write the correct message :(")
    
    [System.Reflection.Assembly]::LoadWithPartialName(“System.Windows.Forms”)
    [Windows.Forms.MessageBox]::Show($message, “”, [Windows.Forms.MessageBoxButtons]::OK, [Windows.Forms.MessageBoxIcon]::Information)
  }

function UI-Toolbox-Ugolini
  {
    # other custom tools
    UI-MessageBox "This tool has been removed."
  }

function UI-Toolbox-Bitman
  {
    # custom PowerShell tools originally written by Mazilu Teodor aka VR Bitman
    [cmdletbinding()] param()

    function OpenRDConnection
      {
        $machine = $SCRIPT:machines[$machine_finder_listbox.SelectedIndex]
        $IPAddress = $machine.Guest.HostName
        mstsc /v:$IPAddress /fullscreen /multimon
      }

    function OpenComputerManagement
      {
        $machine = $SCRIPT:machines[$machine_finder_listbox.SelectedIndex]
        $IPAddress = $machine.Guest.HostName
        compmgmt.msc /computer:\\$IPAddress
      }

    function MachineDetails
      {
        $machine = $SCRIPT:machines[$machine_finder_listbox.SelectedIndex]

        $vmhost = Get-View $machine.runtime.host
        $vmcluster = (Get-View $vmhost.Parent).Name
        $vmfolder = (Get-View $machine.Parent).name
        $vmdc = (Get-Datacenter -VMHost $vmhost.Name).Name
        $vmpath = "PATH:`r`n`r`nDatacenter $vmdc -> Cluster $vmcluster -> Host $($vmhost.Name) -> VM $($machine.name)`r`n(folder: $vmfolder)`r`n`r`n`r`n`r`n"
        $info = "GENERAL INFORMATION:" + ($machine | Select GuestHeartbeatStatus, OverallStatus, ConfigStatus, Name, DisabledMethod, AlarmActionsEnabled, AvailableField | Out-String)
        $additional_info = "GUEST INFORMATION:" + ($machine.Guest | Select * -ExcludeProperty Net, IpStack, Disk, Screen, GenerationInfo, DynamicType, DynamicProperty |  Out-String)
        $vmfiles = "FILES:`r`n" + ($machine.LayoutEx.File | Select Name, @{N="Size (GB)";E={[math]::Round($_.Size / [math]::pow(1024,3))}} | FT -Auto | Out-String)
        $nics_output = "`r`nNETWORK ADAPTERS:`r`n`r`n"
        $nics = $machine.Config.Hardware.Device | ? MacAddress
        ForEach ($n in $nics)
          {
            $out = $n | Select AddressType, MacAddress, WakeOnLanEnabled, @{N="Label";E={$_ | Select -ExpandProperty DeviceInfo | Select -ExpandProperty Label}}, @{N="Summary";E={$_ | Select -ExpandProperty DeviceInfo | Select -ExpandProperty Summary}} | Out-String
            $out = $out.remove(1,3) # cleans first white lines
            $out = $out.remove($out.length-8,8) # cleans last white lines
            $nics_output += ($out + "`r`n`r`n")
          }
        $networks_output = "`r`n`r`nNETWORKS:`r`n`r`n"
        $networks = $machine.network
        ForEach ($n in $networks)
          {
            $network = Get-View $n
            if ($network.Config)
              {
                $out = ($network.Config | Select Name, DistributedVirtualSwitch, Description, AutoExpand | FL | Out-String) 
                $out = $out.remove(1,3) # cleans first white lines
                $out = $out.remove($out.length-8,8) # cleans last white lines
                $networks_output += ($out + "`r`n`r`n")
              }
            else
              {
                $out = ($network.Summary | Select Name, Accessible, IpPoolName | FL | Out-String) 
                $out = $out.remove(1,3) # cleans first white lines
                $out = $out.remove($out.length-8,8) # cleans last white lines
                $networks_output += ($out + "`r`n`r`n")
              }
          }
        $networks_details = "`r`n`r`nNETWORK ADDRESSES:" + ($machine.Guest.Net | Select * -ExcludeProperty DeviceConfigId, DnsConfig, IpConfig, DynamicType, DynamicProperty | Out-String)
        $capabilities = "CAPABILITIES:" + ($machine.Capability | Select * -ExcludeProperty DynamicType, DynamicProperty | Out-String)
        $capabilities += "HOT ADD CAPABILITIES:" + ($machine.Config | Select MemoryHotAddEnabled, CpuHotAddEnabled, CpuHotRemoveEnabled, HotPlugMemoryLimit, HotPlugMemoryIncrementSize | Out-String)
        $perf_stats = "PERFORMANCE QUICK STATS:" + ($machine.Summary.QuickStats | Select * -ExcludeProperty DynamicType, DynamicProperty | Out-String)
        $boot_options = "BOOT OPTIONS:" + ($machine.Config.BootOptions | Select * -ExcludeProperty DynamicType, DynamicProperty | Out-String)
        $customvalues = $machine.summary.customvalue | Select Value,Key
        $customfields = $machine.AvailableField | Select Name,Key
        $customattr = "CUSTOM ATTRIBUTES & ANNOTATIONS:`r`n`r`n"
        ForEach ($r in $customfields)
          {
            $f = ""
            ForEach ($r2 in $customvalues) { if ($r.Key -eq $r2.Key) { $f = $r2.Value } }
            $customattr += ($r.Name + ": " + $f + "`r`n")
          }
        $annotations = ($machine.summary.config.annotation -replace "`n", "`r`n")

        UI-SimpleChildForm ($vmpath + $info + $additional_info + $vmfiles + $nics_output + $networks_output + $networks_details + $capabilities + $perf_stats + $boot_options + $customattr + $annotations)
      }

    function VMStatusDetails
      {
        $machine = $SCRIPT:machines[$machine_finder_listbox.SelectedIndex]

        $conn_state = "VM connection state: " + ($machine.Runtime.ConnectionState | Out-String)
        $pwr_state = "VM power state: " + ($machine.Runtime.PowerState | Out-String)
        $ha_state = "VM HA protected: " + ($machine.Runtime.DasVmProtection.DasProtected | Out-String)
        $tools_status = "VM tools status: " + ($machine.Guest.ToolsStatus | Out-String)
        $tools_run_status = "VM tools running status: " + ($machine.Guest.ToolsRunningStatus | Out-String)
        $guest_state = "VM guest state: " + ($machine.Guest.GuestState | Out-String)
        $boot_req = "VM has install boot required: " + ($machine.Summary.Config.InstallBootRequired | Out-String)
        $heartbeat_status = "VM guest heartbeat status: " + ($machine.GuestHeartbeatStatus | Out-String)
        $config_status = "VM configuration status: " + ($machine.ConfigStatus | Out-String)
        $overall_status = "VM overall status (if not green, see alarms below): " + ($machine.OverallStatus | Out-String)
        $alarms_output = "`r`nAlarms: none."
        if (($machine.OverallStatus -ne $null) -and ($machine.OverallStatus -ne "green"))
          {
            $alarms_output = "`r`nAlarms: `r`n"
            if ($machine.TriggeredAlarmState -ne $null)
              {
                $alarms = $machine.TriggeredAlarmState
                $alarms | % { $alarm = Get-View $_.alarm; $alarms_output += ($alarm.info.Name + " (" + $alarm.info.Description + ") (freq. secs " + $alarm.info.Setting.ReportingFrequency + ")`r`n")}
              }
          }

        UI-SimpleChildForm ($conn_state + $pwr_state + $ha_state + $tools_status + $tools_run_status + $guest_state + $boot_req + $heartbeat_status + $config_status + $overall_status + $alarms_output)
      }

    function VMSnapshotDetails
      {
        $machine = $SCRIPT:machines[$machine_finder_listbox.SelectedIndex]                                              
        Write-Verbose "Retrieving snapshots list for $machine"

        $snapshots = "This is not yet implemented."

        UI-SimpleChildForm ($snapshots)
      }
      
    function ShowWinFilesystems
      {
        $machine = $SCRIPT:machines[$machine_finder_listbox.SelectedIndex]
        $disks = Get-WmiObject Win32_LogicalDisk -ComputerName $machine.Guest.Hostname  | Select DeviceID, FreeSpace, Size | ? FreeSpace
        if ($disks)
          {
            $child_form = New-Object System.Windows.Forms.Form
            $content_textbox = New-Object System.Windows.Forms.TextBox
            $InitialFormWindowState = New-Object System.Windows.Forms.FormWindowState

            $child_form_onload = { $child_form.WindowState = $InitialFormWindowState }
            $child_form.BackColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
            $child_form.ClientSize = New-Object System.Drawing.Size(165,(40 + 20 * ($disks | Measure).Count))
            $child_form.DataBindings.DefaultDataSourceUpdateMode = 0
            $child_form.FormBorderStyle = 5
            $child_form.Name = "child_form"
            $child_form.StartPosition = 4
            $child_form.Text = "Filesystems"
            $child_form.TopMost = $True
            $child_form.add_Load($child_form_onload)
            $InitialFormWindowState = $child_form.WindowState 

            [int] $i = 0
            $SCRIPT:filesystem_commands = @()
            ForEach ($disk in $disks)
              {
                Write-Verbose "Creating link for drive $($disk.DeviceID) .."
                $lbl = New-Object System.Windows.Forms.LinkLabel
                $lbl.DataBindings.DefaultDataSourceUpdateMode = 0
                $lbl.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
                $lbl.LinkColor = [System.Drawing.Color]::FromArgb(255,0,0,0)
                $lbl.Location = New-Object System.Drawing.Point(20,(20 + 20 * $i))
                $lbl.Name = "machine_finder_fs_lbl_$i"
                $lbl.Size = New-Object System.Drawing.Size(300,16)
                $lbl.TabStop = $false
                $lbl.Text = "$($disk.DeviceID) $([math]::Round($disk.Size / [math]::pow(1024,3))) GB | free $([math]::Round($disk.FreeSpace / [math]::pow(1024,3))) GB"
                $str = ("explorer \\" + $machine.Guest.Hostname + "\$($disk.DeviceID[0])$")
                Write-Verbose "Attaching OnClick command: $str"
                $SCRIPT:filesystem_commands += $str
                $lbl.add_Click({ Invoke-Expression -Command "$($SCRIPT:filesystem_commands[([int]$this.name[-1])-48])" }) # I know..
                $child_form.Controls.Add($lbl)
                Write-Verbose "Created filesystem link  $($lbl.Name) .."
                $i++
              }
          }

        $child_form.ShowDialog()| Out-Null
      }

    function ExploreMachine
      {
        $str = ("\\" + ($SCRIPT:machines[$machine_finder_listbox.SelectedIndex].Guest.HostName))
        $command = "explorer " + $str
        Write-Verbose "About to run: $command"
        Invoke-Expression -Command $command
      }

    function ResetVM
      {
        $machine = $SCRIPT:machines[$machine_finder_listbox.SelectedIndex]                                              
        Write-Verbose "User wants to reset VM $($machine.Name), asking for confirmation.."
        
        [void][System.Reflection.Assembly]::LoadWithPartialName(‘Microsoft.VisualBasic’)
        $result = [Microsoft.VisualBasic.Interaction]::MsgBox(“Do you confirm?”, ‘YesNo,Question’, “Please confirm”)
        switch ($result) 
          {
            ‘Yes’ { Write-Verbose "User confirmed VM reset operation, proceeding.."; $machine.ResetVM() }
            ‘No’  { Write-Verbose "User did not confirm VM reset operation, exiting.." }
          }
      }

    function ViewTasksEvents
      {
        $machine = $SCRIPT:machines[$machine_finder_listbox.SelectedIndex]
        
        # gets the tasks of a given VM (max 100, max last 7 days)
        Write-Verbose "Collecting tasks for VM $($machine.Name)"
        $taskManager = Get-View TaskManager
        $vmMoRef = $machine.MoRef
        $tasks_output = @()

        $spec = New-Object VMware.Vim.TaskFilterSpec
        $spec.time = New-Object VMware.Vim.TaskFilterSpecByTime
        $spec.time.beginTime = (Get-Date).AddDays(-7)
        $spec.entity = New-Object VMware.Vim.TaskFilterSpecByEntity
        $spec.entity.entity = $vmMoRef
        $taskHistoryCollectorMoRef = $taskManager.CreateCollectorForTasks($spec)
        $thCol = Get-View -Id $taskHistoryCollectorMoRef
        #$thCol.RewindCollector()

        Write-Verbose "Reading tasks and filtering columns.."
        $tasks = $thCol.ReadNextTasks(100)
        $tasks | % { $tasks_output += ($_ | Select DescriptionId,@{N='User';E={$_.Reason.UserName}},State,Progress,Cancelled,Error,startTime,completeTime) }
        
        if ($tasks_output -eq $null) { $tasks_output = "N/A" }

        Write-Verbose "Tasks info collection completed, displaying child form.."
        UI-SimpleChildForm ($tasks_output | FT -Auto | Out-String)
      }

    function AdministerVM([string]$str)
      {
        $machine = $SCRIPT:machines[$machine_finder_listbox.SelectedIndex]                                              
        Write-Verbose "User wants to '$str' VM $($machine.Name), asking for confirmation.."
        
        [void][System.Reflection.Assembly]::LoadWithPartialName(‘Microsoft.VisualBasic’)
        $result = [Microsoft.VisualBasic.Interaction]::MsgBox(“Do you confirm?”, ‘YesNo,Question’, “Please confirm”)
        switch ($result) 
          {
            ‘Yes’ { 
                    Write-Verbose "User confirmed VM power operation, proceeding.."
                    switch ($str)
                      {
                        'Power On' { $machine.PowerOnVM($null) }
                        'Power Off' { $machine.PowerOffVM() }
                        'Suspend' { $machine.SuspendVM() }
                        'Shutdown Guest' { $machine.ShutdownGuest() }
                        'Restart Guest' { $machine.RebootGuest() }
                      }
                  }
            ‘No’ { Write-Verbose "User did not confirm VM power operation, exiting.." }
          }
      }

    function FindMachines([string]$str)
      {
        $machine_finder_listbox.Items.Clear()
        $machine_finder_button.Enabled = $machine_finder_button2.Enabled = $machine_copier_button.Enabled = $false
        $machine_finder_listBox.Visible = $machine_copier_button.Visible = $machine_finder_button.Visible = $machine_finder_button2.Visible = $false
        $machine_finder_querying_label.Visible = $true
        $machine_finder_reachable_label.Visible = $machine_finder_picturebox.Visible = $false
        $machine_finder_clustered_label.Visible = $machine_finder_vcenter_status_label.Visible = $machine_finder_snapshot_label.Visible = $false
        $SCRIPT:machine_finder_listBox_orig_selectedindex = -1
                                                  
        Write-Verbose "Searching for filesystem links to destroy (machine finder section).."
        Write-Verbose "I have $(($SCRIPT:filesystem_links | Measure).Count) links to destroy."
        if (($SCRIPT:filesystem_links | Measure).Count -gt 0)
          {
            $SCRIPT:filesystem_links | % { $_.Dispose() }
          }

        if ($SCRIPT:machine_finder_cpu_label) { $SCRIPT:machine_finder_cpu_label.Dispose() }
        if ($SCRIPT:machine_finder_ram_label) { $SCRIPT:machine_finder_ram_label.Dispose() }
        if ($SCRIPT:machine_finder_uptime_label) { $SCRIPT:machine_finder_uptime_label.Dispose() }
        if ($SCRIPT:machine_finder_vcenter_uptime_label) { $SCRIPT:machine_finder_vcenter_uptime_label.Dispose() }
        if ($SCRIPT:machine_finder_vcenter_uptime2_label) { $SCRIPT:machine_finder_vcenter_uptime2_label.Dispose() }
        if ($SCRIPT:machine_finder_sessions_label) { $SCRIPT:machine_finder_sessions_label.Dispose() }
        if ($SCRIPT:machine_finder_OS_label) { $SCRIPT:machine_finder_OS_label.Dispose() }
        if ($SCRIPT:machine_finder_strg_label) { $SCRIPT:machine_finder_strg_label.Dispose() }
        if ($SCRIPT:machine_finder_FQDN_label) { $SCRIPT:machine_finder_FQDN_label.Dispose() }

        Write-Verbose "Connecting to the default vCenter Server ($SCRIPT:default_vcenter_server).."
        Connect-VIServer -Server $SCRIPT:default_vcenter_server -WarningAction SilentlyContinue

        Write-Verbose "Searching machines using string: $str"
        $SCRIPT:machines = Get-View -ViewType VirtualMachine -Filter @{"Name"=$str} | Sort Name
        Write-Verbose "Found $(($SCRIPT:machines | measure).count) results"
        if (($SCRIPT:machines | measure).count)
          {
            $machine_finder_listBox.Visible = $machine_copier_button.Visible = $machine_finder_button.Visible = $machine_finder_button2.Visible = $true
            $machine_finder_querying_label.Visible = $false
            $SCRIPT:machines | % {
                                   Write-Verbose "Found machine: $($_.Name)`t`tstate: $($_.Summary.Runtime.PowerState)" # Runtime.PowerState is always available whether VMware Tools is installed or not
                                   [void] $machine_finder_listBox.Items.Add("$($_.Name) (state: $($_.Summary.Runtime.PowerState))")
                                 }
          }
        else 
          {
            UI-MessageBox "Found nothing!"
            $machine_finder_querying_label.Visible = $false
            $machine_finder_button.Visible = $machine_finder_button2.Visible = $true
          }
        $machine_finder_button.Enabled = $machine_finder_button2.Enabled = $true
      }

    function FindMachinesDeep([string]$str)
      {
        $machine_finder_listbox.Items.Clear()
        $machine_finder_button.Enabled = $machine_finder_button2.Enabled = $machine_copier_button.Enabled = $false
        $machine_finder_listBox.Visible = $machine_copier_button.Visible = $machine_finder_button.Visible = $machine_finder_button2.Visible = $false
        $machine_finder_querying_label.Visible = $true
        $machine_finder_reachable_label.Visible = $machine_finder_picturebox.Visible = $false
        $machine_finder_clustered_label.Visible = $machine_finder_vcenter_status_label.Visible = $false
        $SCRIPT:machine_finder_listBox_orig_selectedindex = -1
        $machine_finder_querying_label_orig_text = $machine_finder_querying_label.Text
        $machine_finder_querying_label.Text = "Taking a deeper look on vCenter.."
                                                  
        Write-Verbose "Searching for filesystem links to destroy (machine finder section).."
        Write-Verbose "I have $(($SCRIPT:filesystem_links | Measure).Count) links to destroy."
        if (($SCRIPT:filesystem_links | Measure).Count -gt 0)
          {
            $SCRIPT:filesystem_links | % { $_.Dispose() }
          }

        if ($SCRIPT:machine_finder_cpu_label) { $SCRIPT:machine_finder_cpu_label.Dispose() }
        if ($SCRIPT:machine_finder_ram_label) { $SCRIPT:machine_finder_ram_label.Dispose() }
        if ($SCRIPT:machine_finder_uptime_label) { $SCRIPT:machine_finder_uptime_label.Dispose() }
        if ($SCRIPT:machine_finder_vcenter_uptime_label) { $SCRIPT:machine_finder_vcenter_uptime_label.Dispose() }
        if ($SCRIPT:machine_finder_vcenter_uptime2_label) { $SCRIPT:machine_finder_vcenter_uptime2_label.Dispose() }
        if ($SCRIPT:machine_finder_sessions_label) { $SCRIPT:machine_finder_sessions_label.Dispose() }
        if ($SCRIPT:machine_finder_OS_label) { $SCRIPT:machine_finder_OS_label.Dispose() }
        if ($SCRIPT:machine_finder_strg_label) { $SCRIPT:machine_finder_strg_label.Dispose() }
        if ($SCRIPT:machine_finder_FQDN_label) { $SCRIPT:machine_finder_FQDN_label.Dispose() }

        Write-Verbose "Connecting to the default vCenter Server ($SCRIPT:default_vcenter_server).."
        Connect-VIServer -Server $SCRIPT:default_vcenter_server -WarningAction SilentlyContinue

        Write-Verbose "Searching (deep mode, looking ad DNS hostnames as well) machines using string: $str"
        $SCRIPT:machines = @()
        $machines1 = @()
        $machines2 = @()
        $machines1 = Get-View -ViewType VirtualMachine -Filter @{"Name"=$str}
        $machines2 = Get-View -ViewType VirtualMachine -Filter @{"Guest.Hostname"=$str}
        $SCRIPT:machines = ($machines1 + $machines2) | Sort Name -Unique
        Write-Verbose "Found $(($SCRIPT:machines | measure).count) results"
        if (($SCRIPT:machines | measure).count)
          {
            $machine_finder_listBox.Visible = $machine_copier_button.Visible = $machine_finder_button.Visible = $machine_finder_button2.Visible = $true
            $machine_finder_querying_label.Visible = $false
            $SCRIPT:machines | % {
                                   Write-Verbose "Found machine: $($_.Name)`t`tstate: $($_.Summary.Runtime.PowerState)" # Runtime.PowerState is always available whether VMware Tools is installed or not
                                   [void] $machine_finder_listBox.Items.Add("$($_.Name) (state: $($_.Summary.Runtime.PowerState))")
                                 }
          }
        else 
          {
            UI-MessageBox "Found nothing!"
            $machine_finder_querying_label.Visible = $false
            $machine_finder_button.Visible = $machine_finder_button2.Visible = $true
          }
        $machine_finder_querying_label.Text = $machine_finder_querying_label_orig_text
        $machine_finder_button.Enabled = $machine_finder_button2.Enabled = $true
      }

    function FindUsers([string]$str)
      {
        $user_copier_button.Visible = $false
        $user_finder_querying_label.Visible = $true
        $user_finder_listbox.Items.Clear()
        $user_finder_button.Enabled = $false
        $user_copier_button.Enabled = $false
        $user_finder_listBox.Visible = $false
        $user_finder_picturebox.Visible = $false
        $passwordexpired_label.Visible = $false
        $accountdisabled_label.Visible = $false
        $accountlocked_label.Visible = $false
        $accountunlock_link.Visible = $false
        $Identity = "*$($str)*"
        $i = 0
        Write-Verbose "Searching users using string: $str"
       
        $User = Get-ADUser -Properties * -Filter {(Name -like $Identity) -or (SamAccountName -like $Identity) -or (DisplayName -like $Identity) -or (givenName -like $Identity)}
        Write-Verbose "Found $(($User | measure).count) results"
        if (($User | measure).count)
          {
            $user_finder_listBox.Visible = $true
            $user_finder_querying_label.Visible = $false
            $user_copier_button.Visible = $true
            $User | % {
                        if ($_.Enabled) { $Status = "Enabled" } else { $Status = "Disabled" }
                        Write-Verbose "Found user: $($i). $($_.SamAccountName)`t`t$($_.Name)`t`tStatus: $($Status)"
                        $i++
                        [void] $user_finder_listBox.Items.Add("$($_.SamAccountName) $($_.Name) (status: $($Status))")
                      }
          }
        else 
          {
            UI-MessageBox "Found nothing!"
            $user_finder_querying_label.Visible = $false
          }
        $user_finder_button.Enabled = $true
        
      }

    function FindExchangeObjects([string]$str)
      {
        $mailbox_copier_button.Visible = $false
        $mailbox_finder_querying_label.Visible = $true
        $mailbox_finder_listbox.Items.Clear()
        $mailbox_finder_button.Enabled = $false
        $mailbox_copier_button.Enabled = $false
        $mailbox_finder_listBox.Visible = $false
        $mailbox_finder_details_label.Visible = $false
        $SCRIPT:mailbox_finder_listbox_orig_selectedindex = -1
        $Identity = "*$($str)*"
        Write-Verbose "Searching Exchange objects using string: $str"
       
        $DLs = Get-DistributionGroup -Filter {(Name -like $Identity) -or (SamAccountName -like $Identity) -or (DisplayName -like $Identity) -or (SimpleDisplayName -like $Identity)}
        $MBXs = Get-Mailbox -Filter {(Name -like $Identity) -or (SamAccountName -like $Identity) -or (DisplayName -like $Identity) -or (UserPrincipalName -like $Identity) -or (SimpleDisplayName -like $Identity)}
        $DLs_count = ($DLs | measure).Count
        $MBXs_count = ($MBXs | measure).Count
        $SCRIPT:Exchange_objects = @()
        $SCRIPT:Exchange_objects += $DLs
        $SCRIPT:Exchange_objects += $MBXs
        
        Write-Verbose "Found $(($SCRIPT:Exchange_objects | measure).count) total results"
        if (($SCRIPT:Exchange_objects | measure).count)
          {
            $mailbox_finder_listBox.Visible = $true
            $mailbox_finder_querying_label.Visible = $false
            $mailbox_copier_button.Visible = $true
            $SCRIPT:Exchange_objects | % {
                                           Write-Verbose "Found object: $($_.SamAccountName)`t`t$($_.Name)"
                                           [void] $mailbox_finder_listBox.Items.Add("$($_.SamAccountName) [$($_.Name)]")
                                         }
          }
        else 
          {
            UI-MessageBox "Found nothing!"
            $mailbox_finder_querying_label.Visible = $false
          }
        $mailbox_finder_button.Enabled = $true
        
      }

    function Check_common_parameters
      {
        Write-Verbose "Checking common parameters.."
        $SCRIPT:common_parameters = ""
        if ($verbose_checkbox.Checked) { Write-Verbose ("Verbose checkbox checked."); $SCRIPT:common_parameters = $SCRIPT:common_parameters + " -Verbose" }
        if ($debug_checkbox.Checked) { Write-Verbose ("Debug checkbox checked."); $SCRIPT:common_parameters = $SCRIPT:common_parameters + " -debug" }
        Write-Verbose "Common parameters have been set to: <$SCRIPT:common_parameters>"
      }

    function ShowAcl($path, $SAM)
      {
        if (Test-Path $path)
          {
            if ($SAM)
              {
                Write-Verbose "Executing: Get-Acl on path $($path) filtering by SamAccountName $($SAM)"
                $acl = Get-Acl $path | Select -ExpandProperty Access | Where { $_.IdentityReference -match $SAM} | Out-String
              }
            else
              {
                $acl = Get-Acl $path | Select -ExpandProperty Access | Select FileSystemRights, AccessControlType, IdentityReference, IsInherited | FL | Out-String
              }
            UI-SimpleChildForm($acl)
          }
        else
          {
            UI-MessageBox "Path does not appear to be valid!"
          }
      }

    function ShowUserDetails([string]$SAM)
      {
        UI-SimpleChildForm(Get-ADuser $SAM -Properties * | Out-String)
      }

    function ADGroupDirectAdd([string]$SAM)
      {

        # setting a few "standard" parameters
        [int] $child_form_height = 72
        [int] $child_form_width = 625
        [int] $standard_button_height = 23
        [int] $standard_button_width = 150
        [int] $standard_y_whitespace = [int] $standard_x_whitespace = 5
        $standard_font = New-Object System.Drawing.Font("Gill Sans MT",9.75,1,3,0)

        # creating a new, hidden until invoked, form
        Write-Verbose "Creating the Add to group child form.."
        $child_form = New-Object System.Windows.Forms.Form
        $child_form.Size = New-Object System.Drawing.Size($child_form_width, $child_form_height)
        $child_form.StartPosition = "CenterScreen"
        $child_form.FormBorderStyle = 'Fixed3D'
        $child_form.MaximizeBox = $false
        $child_form.KeyPreview = $True
        $child_form.Add_KeyDown({ if ($_.KeyCode -eq "Escape") {$child_form.Close()} })
        $child_form.Text = "Add user to group (exact name)"

        Write-Verbose "Creating child form buttons, textboxes and labels.."
        
        Write-Verbose "Creating group finder input box.."
        $group_finder_textbox = New-Object System.Windows.Forms.TextBox
        $group_finder_textbox.DataBindings.DefaultDataSourceUpdateMode = 0
        $group_finder_textbox.Font = New-Object System.Drawing.Font("Lucida Console",8,0,3,0)
        $group_finder_textbox.Location = New-Object System.Drawing.Size($standard_x_whitespace,$standard_y_whitespace)
        $group_finder_textbox.Name = "group_finder_textbox"
        $group_finder_textbox.Size = New-Object System.Drawing.Size(($child_form_width - 185),($standard_button_height + 3))
        $group_finder_textbox.Add_KeyDown({if ($_.KeyCode -eq "Enter") { $group_finder_button.PerformClick() }})
        $group_finder_textbox.Font = New-Object System.Drawing.Font("Gill Sans MT",9,1,3,0)
        $child_form.Controls.Add($group_finder_textbox)

        # creating the ADD button
        Write-Verbose "Creating group finder Add button.."
        $group_adder_button  = New-Object System.Windows.Forms.Button
        $group_adder_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $group_adder_button.Font = $standard_font
        $group_adder_button.Location = New-Object System.Drawing.Size(($standard_x_whitespace*2 + $group_finder_textbox.Size.Width),($standard_y_whitespace - 2))
        $group_adder_button.Name = "group_adder_button"
        $group_adder_button.Size = New-Object System.Drawing.Size(70,23)
        $group_adder_button.Text = "Add"
        $group_adder_button.UseVisualStyleBackColor = $True
        $group_adder_button.add_Click({ if ($group_finder_textbox.Text.Trim() -ne "") 
                                          {
                                            # proceeding to add group to the user's membership
                                            $group = $group_finder_textbox.Text.Trim()
                                            Write-Verbose "Adding user to $($group).."
                                            Add-ADGroupMember -Identity $group -Members $SAM -Confirm:$False
                                            UI-MessageBox "Done (hopefully without errors)."
                                            $childCancelButton.PerformClick()
                                          }
                                      })
        $child_form.Controls.Add($group_adder_button)
        
        # creating the Cancel button
        $childCancelButton = New-Object System.Windows.Forms.Button
        $childCancelButton.Location = New-Object System.Drawing.Size(($group_adder_button.Location.X + $group_adder_button.Size.Width + $standard_x_whitespace),($standard_y_whitespace - 2))
        $childCancelButton.Size = New-Object System.Drawing.Size(($standard_button_width/2), $standard_button_height)
        $childCancelButton.Text = "Cancel"
        $childCancelButton.Font = $standard_font
        $childCancelButton.Add_Click({$child_form.Close()})
        $child_form.Controls.Add($childCancelButton)

        $child_form.ShowDialog()| Out-Null
      }

    function ResetUserPassword([string]$SAM, [string]$pwd)
      {
        Write-Verbose "User clicked reset password for SamAccountName $SAM with option $pwd.."
        Write-Verbose "User wants to reset account password $SAM, asking for confirmation.."
        
        [void][System.Reflection.Assembly]::LoadWithPartialName(‘Microsoft.VisualBasic’)
        $result = [Microsoft.VisualBasic.Interaction]::MsgBox(“Do you confirm?”, ‘YesNo,Question’, “Please confirm”)
        switch ($result) 
          {
            ‘Yes’ { 
                    $newpwd = ConvertTo-SecureString -String $pwd -AsPlainText –Force
                    Set-ADAccountPassword $SAM -NewPassword $newpwd –Reset -PassThru | Set-ADUser -ChangePasswordAtLogon $false
                    UI-MessageBox "Password reset to $pwd. User will not have to change it at next logon."
                    if (-not (Get-ADUser $SAM -Properties PasswordExpired).PasswordExpired) { $passwordexpired_label.Visible = $false } 
                  }
            ‘No’  { Write-Verbose "User did not confirm account password reset operation, exiting.." }
          }
      }

    function EditLogonScript([string]$SAM)
      {
        Write-Verbose "Checking path and presence of logon script for SamAccountName $SAM.."
        Write-Verbose "Retrieving script path for $SAM.."
        $full_path = ""
        $base_path = "\\$curdomain_name\netlogon\"
        $script_path = Get-ADUser $SAM -Properties ScriptPath | Select -ExpandProperty ScriptPath
        if ($script_path) { $full_path = $base_path + $script_path }
        if (($full_path -ne "") -and (Test-Path $full_path)) { notepad $full_path } else { UI-MessageBox "User appears to not have a logon script!" }
      }

    function ToggleAccount
      {
        $SAM = ($user_finder_listbox.SelectedItem -split " ")[0] 
        Write-Verbose "User wants to toggle account $SAM, asking for confirmation.."
        
        [void][System.Reflection.Assembly]::LoadWithPartialName(‘Microsoft.VisualBasic’)
        $result = [Microsoft.VisualBasic.Interaction]::MsgBox(“Do you confirm?”, ‘YesNo,Question’, “Please confirm”)
        switch ($result) 
          {
            ‘Yes’ { 
                    Write-Verbose "User confirmed account toggle operation, proceeding.."; 
                    Write-Verbose "Toggling status for SamAccountName $SAM.."
                    $selected_user = Get-ADUser $SAM -Properties *
                    Set-ADUser $selected_user -Enabled (-not $selected_user.Enabled)
                    $selected_user = Get-ADUser $SAM -Properties *
                    if (-not $selected_user.Enabled) { $accountdisabled_label.Visible = $true } else { $accountdisabled_label.Visible = $false }
                    Write-Verbose "Refreshing user finder listbox.."
                    $user_finder_listbox.Items.Clear()
                    $str = $user_finder_textbox.Text.Trim()
                    $Identity = "*$($str)*"
                    Write-Verbose "Searching users using string: $str"
                    $User = Get-ADUser -Properties * -Filter {(Name -like $Identity) -or (SamAccountName -like $Identity) -or (DisplayName -like $Identity) -or (givenName -like $Identity)}
                    Write-Verbose "Found $(($User | measure).count) results"
                    if (($User | measure).count)
                      {
                        $User | % {
                                    if ($_.Enabled) { $Status = "Enabled" } else { $Status = "Disabled" }
                                    Write-Verbose "Found user: $($_.SamAccountName)`t`t$($_.Name)`t`tStatus: $($Status)"
                                    [void] $user_finder_listBox.Items.Add("$($_.SamAccountName) $($_.Name) (status: $($Status))")
                                  }
                      }
                    UI-MessageBox "Account toggled."
                  }
            ‘No’  { Write-Verbose "User did not confirm account toggle operation, exiting.." }
          }
      }

    #Generated Form Function
    function GenerateForm
      {
        Write-Verbose "Creating UI.."
        #region Import the Assemblies
        [reflection.assembly]::loadwithpartialname("System.Drawing") | Out-Null
        [reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null
        [System.Windows.Forms.Application]::EnableVisualStyles()
        #endregion

        #region Generated Form Objects
        Write-Verbose "Creating the main objects of the main form.."
        $main_form = New-Object System.Windows.Forms.Form
        $vSphere_tools_button = New-Object System.Windows.Forms.Button
        $label13 = New-Object System.Windows.Forms.Label
        $net_tools_big_label = New-Object System.Windows.Forms.Label
        $misc_tools_params_label = New-Object System.Windows.Forms.Label
        $label11 = New-Object System.Windows.Forms.Label
        $label10 = New-Object System.Windows.Forms.Label
        $vSphere_tools_params_listbox = New-Object System.Windows.Forms.TextBox
        $vSphere_tools_combobox = New-Object System.Windows.Forms.ComboBox
        $label9 = New-Object System.Windows.Forms.Label
        $Exchange_tools_button = New-Object System.Windows.Forms.Button
        $net_tools_button = New-Object System.Windows.Forms.Button
        $misc_tools_button = New-Object System.Windows.Forms.Button
        $AD_tools_button = New-Object System.Windows.Forms.Button
        $label8 = New-Object System.Windows.Forms.Label
        $Exchange_tools_params_listbox = New-Object System.Windows.Forms.TextBox
        $net_tools_params_listbox = New-Object System.Windows.Forms.TextBox
        $misc_tools_params_listbox = New-Object System.Windows.Forms.TextBox
        $AD_tools_params_listbox = New-Object System.Windows.Forms.TextBox
        $label7 = New-Object System.Windows.Forms.Label
        $Exchange_tools_combobox = New-Object System.Windows.Forms.ComboBox
        $net_tools_combobox = New-Object System.Windows.Forms.ComboBox
        $misc_tools_combobox = New-Object System.Windows.Forms.ComboBox
        $label6 = New-Object System.Windows.Forms.Label
        $label5 = New-Object System.Windows.Forms.Label
        $AD_tools_combobox = New-Object System.Windows.Forms.ComboBox
        $label4 = New-Object System.Windows.Forms.Label
        $label3 = New-Object System.Windows.Forms.Label
        $label2 = New-Object System.Windows.Forms.Label
        $dest_textbox = New-Object System.Windows.Forms.TextBox
        $source_textbox = New-Object System.Windows.Forms.TextBox
        $tool_selection_label = New-Object System.Windows.Forms.Label
        $parens_label = New-Object System.Windows.Forms.Label
        $Ugo_box_button = New-Object System.Windows.Forms.Button
        $compareusers_button = New-Object System.Windows.Forms.Button
        $comparegroups_button = New-Object System.Windows.Forms.Button
        $run_label = New-Object System.Windows.Forms.Label
        $runCMD_link = New-Object System.Windows.Forms.LinkLabel
        $colon_label = New-Object System.Windows.Forms.Label
        $run_textbox = New-Object System.Windows.Forms.TextBox
        $run_button = New-Object System.Windows.Forms.Button
        $withpath_button = New-Object System.Windows.Forms.Button
        $external_tools_label = New-Object System.Windows.Forms.Label
        $external_tools_myarea_link = New-Object System.Windows.Forms.LinkLabel
        $external_tools_vsphere_link = New-Object System.Windows.Forms.LinkLabel
        $external_tools_tsm_link = New-Object System.Windows.Forms.LinkLabel
        $external_tools_lync_link = New-Object System.Windows.Forms.LinkLabel
        $external_tools_chgaudit_link = New-Object System.Windows.Forms.LinkLabel
        $external_tools_exch13_link = New-Object System.Windows.Forms.LinkLabel
        $external_tools_Simpana_link = New-Object System.Windows.Forms.LinkLabel
        $external_tools_cw_link = New-Object System.Windows.Forms.LinkLabel
        $external_tools_sp13_link = New-Object System.Windows.Forms.LinkLabel
        $external_tools_dsamsc_button = New-Object System.Windows.Forms.Button
        $external_tools_gpmcmsc_button = New-Object System.Windows.Forms.Button
        $external_tools_compmgmt_button = New-Object System.Windows.Forms.Button
        $external_tools_exchangemsc_button = New-Object System.Windows.Forms.Button
        $external_tools_dnsmsc_button = New-Object System.Windows.Forms.Button
        $external_tools_rdpmsc_button = New-Object System.Windows.Forms.Button
        $user_finder_label = New-Object System.Windows.Forms.Label
        $user_finder_textbox = New-Object System.Windows.Forms.TextBox
        $user_finder_button = New-Object System.Windows.Forms.Button
        $user_copier_button = New-Object System.Windows.Forms.Button
        $user_finder_listbox = New-Object System.Windows.Forms.ListBox 
        $user_finder_picturebox = New-Object System.Windows.Forms.PictureBox
        $user_finder_querying_label = New-Object System.Windows.Forms.Label
        $passwordexpired_label = New-Object System.Windows.Forms.Label
        $accountdisabled_label = New-Object System.Windows.Forms.Label
        $accountlocked_label = New-Object System.Windows.Forms.Label
        $accountunlock_link = New-Object System.Windows.Forms.LinkLabel
        $machine_finder_label = New-Object System.Windows.Forms.Label
        $machine_finder_querying_label = New-Object System.Windows.Forms.Label
        $machine_finder_textbox = New-Object System.Windows.Forms.TextBox
        $machine_finder_button = New-Object System.Windows.Forms.Button
        $machine_finder_button2 = New-Object System.Windows.Forms.Button
        $machine_copier_button = New-Object System.Windows.Forms.Button
        $machine_finder_listbox = New-Object System.Windows.Forms.ListBox 
        $SCRIPT:machine_finder_listBox_orig_selectedindex = -1
        $machine_finder_picturebox = New-Object System.Windows.Forms.PictureBox
        $machine_finder_reachable_label = New-Object System.Windows.Forms.Label
        $machine_finder_clustered_label = New-Object System.Windows.Forms.Label
        $machine_finder_vcenter_status_label = New-Object System.Windows.Forms.LinkLabel
        $machine_finder_snapshot_label = New-Object System.Windows.Forms.LinkLabel
        $debug_checkbox = New-Object System.Windows.Forms.CheckBox
        $verbose_checkbox = New-Object System.Windows.Forms.CheckBox
        $AD_tools_help_link = New-Object System.Windows.Forms.LinkLabel
        $Exchange_tools_help_link = New-Object System.Windows.Forms.LinkLabel
        $vSphere_tools_help_link = New-Object System.Windows.Forms.LinkLabel
        $net_tools_help_link = New-Object System.Windows.Forms.LinkLabel
        $misc_tools_help_link = New-Object System.Windows.Forms.LinkLabel
        $main_form_hide_link = New-Object System.Windows.Forms.LinkLabel
        $NotifyIcon= New-Object System.Windows.Forms.NotifyIcon
        $Tray_ContextMenu = New-Object System.Windows.Forms.ContextMenu
        $Tray_Menu_Item_Show = New-Object System.Windows.Forms.MenuItem
        $Tray_Menu_Item_Exit = New-Object System.Windows.Forms.MenuItem
        $label_animation_timer = New-Object System.Windows.Forms.Timer
        $label_animation_timer_simple = New-Object System.Windows.Forms.Timer
        $InitialFormWindowState = New-Object System.Windows.Forms.FormWindowState
        #endregion Generated Form Objects

        Write-Verbose "Setting some vars.."
        $label_animation_standard_interval = 5
        $label_animation_standard_sleep_duration = 350
        $label_animation_simple_sleep_duration = 1000
        $label_animation_max_char_changes = 3
        $SCRIPT:label_animation_char_position = $SCRIPT:label_animation_char_change_count = $SCRIPT:label_animation_max_label_length = 0
        $SCRIPT:label_animation_max_label_length_reduction = 0
        $onload_animations = $true
        $onload_animation_type = 'simple'
        $standard_font = New-Object System.Drawing.Font("Gisha",8,0,3,0)
        $standard_tools_group_width = 275
        $standard_x_whitespace = 15
        $resource_path = $PSScriptRoot + '\Res\'
        if (-not (Test-Path $resource_path)) { Write-Warning "could not find Res subdir! no icons and images are available!" }
        $standard_background_image = $resource_path + 'BT_background.png'
        $standard_user_photo = $resource_path + "user.png"
        $standard_win_img = $resource_path + "windows.png"
        $standard_nonwin_img = $resource_path + "nonwindows.png"
        $standard_unknown_img = $resource_path + "unknown.png"
        $icon1 = New-Object System.Drawing.Icon($resource_path + "BT_bw.ico")

        # generating the list of available tools in the module Bitman.psm1
        Write-Verbose "Generating the list of available tools in the module Bitman.psm1.."
        $module_name = "Bitman"
        $functions = Get-Command -Module $module_name | Select -ExpandProperty Name
    
        #Generated Event Script Blocks
        Write-Verbose "Loading OnClick / OnLoad / OnClose event code.."
        $AD_tools_button_OnClick = {  
                                     $cmd = $AD_tools_combobox.Text.Trim()
                                     $param = $AD_tools_params_listbox.Text.Trim()
                                     Check_common_parameters
                                     $command = "$cmd $param $SCRIPT:common_parameters"
                                     Write-Verbose "About to run command $command"
                                     Invoke-Expression -Command $command | Out-Default
                                   }
        
        $Ugo_box_button_OnClick = { Write-Verbose "Launching Ugo's toolbox.."; Toolbox-Ugolini }
        
        $Exchange_tools_button_OnClick = { 
                                           $cmd = $Exchange_tools_combobox.Text.Trim()
                                           $param = $Exchange_tools_params_listbox.Text.Trim()
                                           Check_common_parameters
                                           $command = "$cmd $param $SCRIPT:common_parameters"
                                           Invoke-Expression -Command $command | Out-Default
                                         }
        
        $vSphere_tools_button_OnClick = { 
                                          $cmd = $vSphere_tools_combobox.Text.Trim()
                                          $param = $vSphere_tools_params_listbox.Text.Trim()
                                          Check_common_parameters
                                          $command = "$cmd $param $SCRIPT:common_parameters"
                                          Invoke-Expression -Command $command | Out-Default
                                        }

        $net_tools_button_OnClick = { 
                                      $cmd = $net_tools_combobox.Text.Trim()
                                      $param = $net_tools_params_listbox.Text.Trim()
                                      Check_common_parameters
                                      $command = "$cmd $param $SCRIPT:common_parameters"
                                      Invoke-Expression -Command $command | Out-Default
                                    }

        $misc_tools_button_OnClick = { 
                                       $cmd = $misc_tools_combobox.Text.Trim()
                                       $param = $misc_tools_params_listbox.Text.Trim()
                                       Check_common_parameters
                                       $command = "$cmd $param $SCRIPT:common_parameters"
                                       Invoke-Expression -Command $command | Out-Default
                                     }
        
        $compareusers_button_OnClick = { 
                                         if (($source_textbox.Text.ToString().Trim() -eq "") -or ($dest_textbox.Text.ToString().Trim() -eq ""))
                                           {
                                             UI-MessageBox "Please input both source and destination Sam Account Names."
                                           }
                                         else
                                           {
                                             Write-Verbose "Launching user compare tool..";
                                             Check_common_parameters
                                             $command = "AD-CompareUsers $($source_textbox.Text.Trim()) $($dest_textbox.Text.Trim()) $SCRIPT:common_parameters"
                                             Invoke-Expression -Command $command | Out-Default
                                           }
                                       }

        $comparegroups_button_OnClick = { 
                                          if (($source_textbox.Text.ToString().Trim() -eq "") -or ($dest_textbox.Text.ToString().Trim() -eq ""))
                                            {
                                              UI-MessageBox "Please input both source and destination group names."
                                            }
                                          else
                                            {
                                              Write-Verbose "Launching group compare tool..";
                                              Check_common_parameters
                                              $command = "AD-CompareGroups $($source_textbox.Text.Trim()) $($dest_textbox.Text.Trim()) $SCRIPT:common_parameters"
                                              Invoke-Expression -Command $command | Out-Default
                                            }
                                        }

        $run_button_OnClick = {
                                $command = $run_textbox.Text.ToString().Trim()
                                if ($command -eq "cmd") { $command = "Start-Job -ScriptBlock { cmd /c start cmd }" }
                                if ((([System.Uri]$command).isUnc) -or (([System.Uri]$command).isAbsoluteUri)) { $command = "explorer " + ($command -replace "&",'"&"') }
                                Write-Verbose "About to run: $command"
                                Invoke-Expression -Command $command
                                # & 'explorer.exe' @("/select", ",", $File)
                              }

        $user_finder_button_OnClick = { 
                                        if ($user_finder_textbox.Text.Trim() -ne "") { FindUsers $user_finder_textbox.Text.Trim() } 
                                      }

        $machine_finder_button_OnClick = { 
                                           if ($machine_finder_textbox.Text.Trim() -ne "") { FindMachines $machine_finder_textbox.Text.Trim() } 
                                         }

        $machine_finder_button2_OnClick = { 
                                            if ($machine_finder_textbox.Text.Trim() -ne "") { FindMachinesDeep $machine_finder_textbox.Text.Trim() } 
                                          }

        $machine_copier_button_OnClick = { 
                                           $str = ($machine_finder_listbox.SelectedItem -split " ")[0] 
                                           Write-Verbose "Copying to clipboard: $str"
                                           $str | Clip
                                         }

        $user_copier_button_OnClick = { 
                                        $str = ($user_finder_listbox.SelectedItem -split " ")[0] 
                                        Write-Verbose "Copying to clipboard: $str"
                                        $str | Clip
                                      }

        $AD_tools_help_link_OnClick = { 
                                        $command = "Get-Help $($AD_tools_combobox.Text.Trim()) -ShowWindow"
                                        Invoke-Expression -Command $command 
                                      }

        $Exchange_tools_help_link_OnClick = { 
                                              $command = "Get-Help $($Exchange_tools_combobox.Text.Trim()) -ShowWindow"
                                              Invoke-Expression -Command $command 
                                            }

        $vSphere_tools_help_link_OnClick = { 
                                             $command = "Get-Help $($vSphere_tools_combobox.Text.Trim()) -ShowWindow"
                                             Invoke-Expression -Command $command 
                                           }

        $net_tools_help_link_OnClick = { 
                                         $command = "Get-Help $($net_tools_combobox.Text.Trim()) -ShowWindow"
                                         Invoke-Expression -Command $command 
                                       }

        $misc_tools_help_link_OnClick = { 
                                          $command = "Get-Help $($misc_tools_combobox.Text.Trim()) -ShowWindow"
                                          Invoke-Expression -Command $command 
                                        }

        $main_form_hide_link_OnClick = { 
                                         Write-Verbose "Minimizing main window.."
                                         $main_form.WindowState = "minimized" 
                                       }

        $mailbox_finder_listBox_MouseDown = {
                                              #Event Argument: $_ = [System.Windows.Forms.MouseEventArgs]
                                              #if ($_.Button -eq [Windows.Forms.MouseButtons]::Right) 
                                               # { 
		                                          $mailbox_finder_listbox.SelectedIndex = $mailbox_finder_listbox.IndexFromPoint($_.X, $_.Y)
                                               # }

                                              Write-Verbose "Mailbox finder listbox selected index: $($mailbox_finder_listbox.SelectedIndex); original listbox index (before click): $SCRIPT:mailbox_finder_listbox_orig_selectedindex"
                                              if (($mailbox_finder_listbox.SelectedIndex -gt -1) -and ($mailbox_finder_listbox.SelectedIndex -ne $SCRIPT:mailbox_finder_listbox_orig_selectedindex))
                                                {
                                                  

                                                  $mailbox_finder_details_label.Visible = $false
                                                  $mailbox_copier_button.Enabled = $true
                                                  
                                                  <# [code] #>
                                                  
                                                  $mailbox_finder_details_label.Visible = $true
                                                  $Exc_object = $SCRIPT:Exchange_objects[$mailbox_finder_listbox.SelectedIndex]

                                                }
                                              $SCRIPT:mailbox_finder_listbox_orig_selectedindex = $mailbox_finder_listbox.SelectedIndex
                                            }

        $machine_finder_listbox_MouseDown = {  
                                              #Event Argument: $_ = [System.Windows.Forms.MouseEventArgs]
                                              #if ($_.Button -eq [Windows.Forms.MouseButtons]::Right) 
                                               # { 
		                                          $machine_finder_listbox.SelectedIndex = $machine_finder_listbox.IndexFromPoint($_.X, $_.Y)
                                               # }

                                              Write-Verbose "Machine finder listbox selected index: $($machine_finder_listbox.SelectedIndex); original listbox index (before click): $SCRIPT:machine_finder_listBox_orig_selectedindex"
                                              if (($machine_finder_listbox.SelectedIndex -gt -1) -and ($machine_finder_listbox.SelectedIndex -ne $SCRIPT:machine_finder_listBox_orig_selectedindex))
                                                {
                                                  
                                                  $machine_finder_reachable_label.Visible = $machine_finder_clustered_label.Visible = $false
                                                  $machine_finder_vcenter_status_label.Visible = $machine_finder_snapshot_label.Visible = $false
                                                  $machine_copier_button.Enabled = $machine_finder_picturebox.Visible = $true
                                                  
                                                  Write-Verbose "Searching for filesystem links to destroy (machine finder section).."
                                                  Write-Verbose "I have $(($SCRIPT:filesystem_links | Measure).Count) links to destroy."
                                                  if (($SCRIPT:filesystem_links | Measure).Count -gt 0)
                                                    {
                                                      $SCRIPT:filesystem_links | % { $_.Dispose() }
                                                    }

                                                  if ($SCRIPT:machine_finder_cpu_label) { $SCRIPT:machine_finder_cpu_label.Dispose() }
                                                  if ($SCRIPT:machine_finder_ram_label) { $SCRIPT:machine_finder_ram_label.Dispose() }
                                                  if ($SCRIPT:machine_finder_uptime_label) { $SCRIPT:machine_finder_uptime_label.Dispose() }
                                                  if ($SCRIPT:machine_finder_vcenter_uptime_label) { $SCRIPT:machine_finder_vcenter_uptime_label.Dispose() }
                                                  if ($SCRIPT:machine_finder_vcenter_uptime2_label) { $SCRIPT:machine_finder_vcenter_uptime2_label.Dispose() }
                                                  if ($SCRIPT:machine_finder_sessions_label) { $SCRIPT:machine_finder_sessions_label.Dispose() }
                                                  if ($SCRIPT:machine_finder_OS_label) { $SCRIPT:machine_finder_OS_label.Dispose() }
                                                  if ($SCRIPT:machine_finder_strg_label) { $SCRIPT:machine_finder_strg_label.Dispose() }
                                                  if ($SCRIPT:machine_finder_FQDN_label) { $SCRIPT:machine_finder_FQDN_label.Dispose() }
                                                  
                                                  $machine = $SCRIPT:machines[$machine_finder_listbox.SelectedIndex]
                                                  $OS = $machine.summary.config.guestFullName
                                                  if ($OS -eq $null) 
                                                    { 
                                                      $machine_finder_picturebox.ImageLocation = $standard_unknown_img
                                                    }
                                                  elseif ($OS -match "Windows") 
                                                    { 
                                                      $machine_finder_picturebox.ImageLocation = $standard_win_img
                                                    }
                                                  else 
                                                    {
                                                      $machine_finder_picturebox.ImageLocation = $standard_nonwin_img
                                                    }
                                                  $IPAddress = $machine.Guest.IPAddress
                                                  $FQDN = $machine.Guest.HostName
                                                  Write-Verbose "About to start a connection test to a remote machine; IP address: $IPAddress - FQDN: $FQDN"
                                                  Write-Verbose "I test with the FQDN because the IP from vCenter might not always be accurate"
                                                  if ($IPAddress -and (Test-Connection $FQDN -Count 1 -Quiet)) # if vCenter doesn't see any IP, it's definitely unreachable
                                                    { 
                                                      $machine_finder_reachable_label.Text = "REACHABLE"
                                                      $machine_finder_reachable_label.ForeColor = [System.Drawing.Color]::FromArgb(255,0,200,0)
                                                    }
                                                  else 
                                                    { 
                                                      $machine_finder_reachable_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,0,0)
                                                      $machine_finder_reachable_label.Text = "UNREACHABLE"
                                                    }
                                                  $machine_finder_reachable_label.Visible = $true

                                                  if (($machine.Runtime.ConnectionState -eq "connected") -and 
                                                      ($machine.Runtime.PowerState -eq "poweredOn") -and
                                                      ($machine.Runtime.DasVmProtection.DasProtected -eq $true) -and
                                                      ($machine.Guest.ToolsStatus -eq "toolsOk") -and
                                                      ($machine.Guest.ToolsRunningStatus -eq "guestToolsRunning") -and
                                                      ($machine.Guest.GuestState -eq "running") -and
                                                      ($machine.Summary.Config.InstallBootRequired -eq $false) -and
                                                      ($machine.GuestHeartbeatStatus -eq "green") -and
                                                      ($machine.OverallStatus -eq "green") -and
                                                      ($machine.ConfigStatus -eq "green"))
                                                    { 
                                                      $machine_finder_vcenter_status_label.Text = "VM status OK"

                                                      $machine_finder_vcenter_status_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
                                                      $machine_finder_vcenter_status_label.LinkColor = [System.Drawing.Color]::FromArgb(255,0,200,0)
                                                    }
                                                  else 
                                                    { 
                                                      $machine_finder_vcenter_status_label.Text = "VM status NOK"
                                                      
                                                      $machine_finder_vcenter_status_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
                                                      $machine_finder_vcenter_status_label.LinkColor = [System.Drawing.Color]::FromArgb(255,255,0,0)
                                                    }
                                                  $machine_finder_vcenter_status_label.Visible = $true


                                                  if ($machine.Snapshot -ne $null) { $machine_finder_snapshot_label.Visible = $true }

                                                  $SCRIPT:machine_finder_FQDN_label = New-Object System.Windows.Forms.Label
                                                  $SCRIPT:machine_finder_FQDN_label.DataBindings.DefaultDataSourceUpdateMode = 0
                                                  $SCRIPT:machine_finder_FQDN_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
                                                  $SCRIPT:machine_finder_FQDN_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
                                                  $SCRIPT:machine_finder_FQDN_label.Location = New-Object System.Drawing.Point(750,235)
                                                  $SCRIPT:machine_finder_FQDN_label.Name = "machine_finder_FQDN_label"
                                                  $SCRIPT:machine_finder_FQDN_label.Size = New-Object System.Drawing.Size(230,16)
                                                  $SCRIPT:machine_finder_FQDN_label.TabStop = $false
                                                  if ($FQDN -eq $null) { $SCRIPT:machine_finder_FQDN_label.Text = "FQDN: N/A" } else { $SCRIPT:machine_finder_FQDN_label.Text = $FQDN}
                                                  $main_form.Controls.Add($SCRIPT:machine_finder_FQDN_label)

                                                  $SCRIPT:machine_finder_OS_label = New-Object System.Windows.Forms.Label
                                                  $SCRIPT:machine_finder_OS_label.DataBindings.DefaultDataSourceUpdateMode = 0
                                                  $SCRIPT:machine_finder_OS_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
                                                  $SCRIPT:machine_finder_OS_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
                                                  $SCRIPT:machine_finder_OS_label.Location = New-Object System.Drawing.Point(750,255)
                                                  $SCRIPT:machine_finder_OS_label.Name = "machine_finder_OS_label"
                                                  $SCRIPT:machine_finder_OS_label.Size = New-Object System.Drawing.Size(230,16)
                                                  $SCRIPT:machine_finder_OS_label.BorderStyle = 0
                                                  $SCRIPT:machine_finder_OS_label.TabStop = $false
                                                  if ($OS -eq $null) { $SCRIPT:machine_finder_OS_label.Text = "OS: N/A" } else { $SCRIPT:machine_finder_OS_label.Text = ("OS: " + ($OS -replace 'Microsoft ',''))}
                                                  $main_form.Controls.Add($SCRIPT:machine_finder_OS_label)
                                                  
                                                  Write-Verbose "Reading VM configuration: NumCPU (total cores) $($machine.Config.Hardware.NumCPU) - NumCoresPerSocket $($machine.Config.Hardware.NumCoresPerSocket)"
                                                  $SCRIPT:machine_finder_cpu_label = New-Object System.Windows.Forms.Label
                                                  $SCRIPT:machine_finder_cpu_label.DataBindings.DefaultDataSourceUpdateMode = 0
                                                  $SCRIPT:machine_finder_cpu_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
                                                  $SCRIPT:machine_finder_cpu_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
                                                  $SCRIPT:machine_finder_cpu_label.Location = New-Object System.Drawing.Point(750,275)
                                                  $SCRIPT:machine_finder_cpu_label.Name = "machine_finder_cpu_label"
                                                  $SCRIPT:machine_finder_cpu_label.Size = New-Object System.Drawing.Size(200,16)
                                                  $SCRIPT:machine_finder_cpu_label.TabStop = $false
                                                  if ($machine.Config.hardware.NumCPU -ne $null)
                                                    {
                                                      $cpu_cores = $machine.Config.Hardware.NumCoresPerSocket
                                                      $cpu_sockets = [math]::Round(($machine.Config.Hardware.NumCPU / $machine.Config.Hardware.NumCoresPerSocket),2)
                                                      $SCRIPT:machine_finder_cpu_label.Text = "CPU: $($cpu_cores)C x $($cpu_sockets)S"
                                                    }
                                                  else
                                                    {
                                                      $SCRIPT:machine_finder_cpu_label.Text = "CPU: N/A"
                                                    }
                                                  $main_form.Controls.Add($SCRIPT:machine_finder_cpu_label)

                                                  Write-Verbose "Reading VM configuration: MemoryMB $($machine.Config.Hardware.MemoryMB)"
                                                  Write-Verbose "Reading VM stat: HostMemoryUsage $($machine.Summary.QuickStats.HostMemoryUsage)"
                                                  $SCRIPT:machine_finder_ram_label = New-Object System.Windows.Forms.Label
                                                  $SCRIPT:machine_finder_ram_label.DataBindings.DefaultDataSourceUpdateMode = 0
                                                  $SCRIPT:machine_finder_ram_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
                                                  $SCRIPT:machine_finder_ram_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
                                                  $SCRIPT:machine_finder_ram_label.Location = New-Object System.Drawing.Point(750,295)
                                                  $SCRIPT:machine_finder_ram_label.Name = "machine_finder_ram_label"
                                                  $SCRIPT:machine_finder_ram_label.Size = New-Object System.Drawing.Size(200,16)
                                                  $SCRIPT:machine_finder_ram_label.TabStop = $false
                                                  if ($machine.Config.hardware.memoryMB -ne $null)
                                                    {
                                                      $ramGB = [math]::Round($machine.Config.Hardware.MemoryMB / 1024)
                                                      $SCRIPT:machine_finder_ram_label.Text = "RAM: $ramGB GB (usage: aprox. $([math]::Round(($machine.Summary.QuickStats.HostMemoryUsage*100)/$machine.Config.Hardware.MemoryMB))%)"
                                                    }
                                                  else
                                                    {
                                                      $SCRIPT:machine_finder_ram_label.Text = "RAM: N/A"
                                                    }
                                                  $main_form.Controls.Add($SCRIPT:machine_finder_ram_label)

                                                  Write-Verbose "Reading VM stat: Storage.PerDatastoreUsage.Committed $($machine.Storage.PerDatastoreUsage.Committed)"
                                                  $SCRIPT:machine_finder_strg_label = New-Object System.Windows.Forms.Label
                                                  $SCRIPT:machine_finder_strg_label.DataBindings.DefaultDataSourceUpdateMode = 0
                                                  $SCRIPT:machine_finder_strg_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
                                                  $SCRIPT:machine_finder_strg_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
                                                  $SCRIPT:machine_finder_strg_label.Location = New-Object System.Drawing.Point(750,315)
                                                  $SCRIPT:machine_finder_strg_label.Name = "machine_finder_strg_label"
                                                  $SCRIPT:machine_finder_strg_label.Size = New-Object System.Drawing.Size(230,16)
                                                  $SCRIPT:machine_finder_strg_label.TabStop = $false
                                                  if ($machine.Storage.PerDatastoreUsage.Committed -ne $null)
                                                    {
                                                      $storageGB = [math]::Round(($machine.Storage.PerDatastoreUsage.Committed | Measure -Sum).Sum / [math]::pow(1024,3))
                                                      $SCRIPT:machine_finder_strg_label.Text = "DS storage: $($storageGB) GB used (excl. any RDM)"
                                                    }
                                                  else
                                                    {
                                                      $SCRIPT:machine_finder_strg_label.Text = "Storage: N/A"
                                                    }
                                                  $main_form.Controls.Add($SCRIPT:machine_finder_strg_label)

                                                  Write-Verbose "Reading VM configuration: UptimeSeconds $($machine.Summary.QuickStats.UptimeSeconds)"
                                                  $uptime = (Get-Date) - (New-TimeSpan -Seconds $machine.Summary.QuickStats.UptimeSeconds)
                                                  $SCRIPT:machine_finder_vcenter_uptime_label = New-Object System.Windows.Forms.Label
                                                  $SCRIPT:machine_finder_vcenter_uptime_label.DataBindings.DefaultDataSourceUpdateMode = 0
                                                  $SCRIPT:machine_finder_vcenter_uptime_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
                                                  $SCRIPT:machine_finder_vcenter_uptime_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
                                                  $SCRIPT:machine_finder_vcenter_uptime_label.Location = New-Object System.Drawing.Point(750,375)
                                                  $SCRIPT:machine_finder_vcenter_uptime_label.Name = "machine_finder_vcenter_uptime_label"
                                                  $SCRIPT:machine_finder_vcenter_uptime_label.Size = New-Object System.Drawing.Size(210,16)
                                                  $SCRIPT:machine_finder_vcenter_uptime_label.TabStop = $false
                                                  $SCRIPT:machine_finder_vcenter_uptime_label.Text = "Last VM poweron: $uptime"
                                                  $main_form.Controls.Add($SCRIPT:machine_finder_vcenter_uptime_label)

                                                  Write-Verbose "Reading VM configuration: BootTime $($machine.Runtime.BootTime)"
                                                  if ($machine.Runtime.BootTime -ne $null) { $uptime2 = $machine.Runtime.BootTime } else { $uptime2 = "N/A" }
                                                  $SCRIPT:machine_finder_vcenter_uptime2_label = New-Object System.Windows.Forms.Label
                                                  $SCRIPT:machine_finder_vcenter_uptime2_label.DataBindings.DefaultDataSourceUpdateMode = 0
                                                  $SCRIPT:machine_finder_vcenter_uptime2_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
                                                  $SCRIPT:machine_finder_vcenter_uptime2_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
                                                  $SCRIPT:machine_finder_vcenter_uptime2_label.Location = New-Object System.Drawing.Point(750,395)
                                                  $SCRIPT:machine_finder_vcenter_uptime2_label.Name = "machine_finder_vcenter_uptime2_label"
                                                  $SCRIPT:machine_finder_vcenter_uptime2_label.Size = New-Object System.Drawing.Size(210,16)
                                                  $SCRIPT:machine_finder_vcenter_uptime2_label.TabStop = $false
                                                  $SCRIPT:machine_finder_vcenter_uptime2_label.Text = "Last VM boot: $uptime2"
                                                  $main_form.Controls.Add($SCRIPT:machine_finder_vcenter_uptime2_label)

                                                  if ($machine_finder_reachable_label.Text -eq "REACHABLE")
                                                    {
                                                      if ($OS -match "Windows")
                                                        {
                                                          $clussvc = Get-Service -Name ClusSvc -ComputerName $machine.Guest.Hostname -ErrorAction SilentlyContinue
                                                          if ($clussvc) { $machine_finder_clustered_label.Visible = $true }

                                                          Write-Verbose "Reading VM in-guest CPU usage"
                                                          $cpu_usage = ((Get-WmiObject Win32_Processor -ComputerName $machine.Guest.Hostname | Select LoadPercentage).LoadPercentage | Measure -Average).Average
                                                          Write-Verbose "CPU usage is: $cpu_usage"
                                                          $SCRIPT:machine_finder_cpu_label.Text += " (usage: avg. $($cpu_usage)%)"
                                                          
                                                          Write-Verbose "Reading VM in-guest sessions"
                                                          $sessions = AD-GetComputerSessions $machine.Guest.HostName
                                                          if ($sessions -eq $null)
                                                            {
                                                              Write-Verbose "AD-GetComputerSessions failed to execute or returned nothing, setting session counts to 'N/A'"
                                                              $active_sessions_count = $disc_sessions_count = "N/A"
                                                            }
                                                          else
                                                            {
                                                              $active_sessions = $sessions | Where { $_.State -eq "Active" }
                                                              $disc_sessions = $sessions | Where { $_.State -eq "Disc" }
                                                              $active_sessions_count = ($active_sessions | Measure).Count
                                                              $disc_sessions_count = ($disc_sessions | Measure).Count
                                                              Write-Verbose "Active sessions count: $active_sessions_count"
                                                              Write-Verbose "Disconnected sessions count: $disc_sessions_count"
                                                            }
                                                          $SCRIPT:machine_finder_sessions_label = New-Object System.Windows.Forms.Label
                                                          $SCRIPT:machine_finder_sessions_label.DataBindings.DefaultDataSourceUpdateMode = 0
                                                          $SCRIPT:machine_finder_sessions_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
                                                          $SCRIPT:machine_finder_sessions_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
                                                          $SCRIPT:machine_finder_sessions_label.Location = New-Object System.Drawing.Point(750,335)
                                                          $SCRIPT:machine_finder_sessions_label.Name = "machine_finder_sessions_label"
                                                          $SCRIPT:machine_finder_sessions_label.Size = New-Object System.Drawing.Size(230,16)
                                                          $SCRIPT:machine_finder_sessions_label.TabStop = $false
                                                          $SCRIPT:machine_finder_sessions_label.Text = "Sessions: $active_sessions_count active | $disc_sessions_count disconnected"
                                                          $main_form.Controls.Add($SCRIPT:machine_finder_sessions_label)

                                                          $uptime = Get-WmiObject win32_operatingsystem -ComputerName $machine.Guest.Hostname | Select @{LABEL=’LastBootUpTime’;EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}
                                                          Write-Verbose "Reading Windows OS WMI uptime: $uptime"
                                                          $SCRIPT:machine_finder_uptime_label = New-Object System.Windows.Forms.Label
                                                          $SCRIPT:machine_finder_uptime_label.DataBindings.DefaultDataSourceUpdateMode = 0
                                                          $SCRIPT:machine_finder_uptime_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
                                                          $SCRIPT:machine_finder_uptime_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
                                                          $SCRIPT:machine_finder_uptime_label.Location = New-Object System.Drawing.Point(750,355)
                                                          $SCRIPT:machine_finder_uptime_label.Name = "machine_finder_uptime_label"
                                                          $SCRIPT:machine_finder_uptime_label.Size = New-Object System.Drawing.Size(200,32)
                                                          $SCRIPT:machine_finder_uptime_label.TabStop = $false
                                                          $SCRIPT:machine_finder_uptime_label.Text = "OS uptime: $($uptime.LastBootUpTime)"
                                                          $main_form.Controls.Add($SCRIPT:machine_finder_uptime_label)
                                                      
                                                          $disks = Get-WmiObject Win32_LogicalDisk -ComputerName $machine.Guest.Hostname  | Select DeviceID, FreeSpace, Size | ? FreeSpace
                                                          if ($disks)
                                                            {
                                                              [int] $i = 0
                                                              $SCRIPT:filesystem_commands = @()
                                                              $SCRIPT:filesystem_links = @()
                                                              ForEach ($disk in $disks)
                                                                {
                                                                  if ($i -le 7)
                                                                    {
                                                                      Write-Verbose "Creating link for drive $($disk.DeviceID) .."
                                                                      $lbl = New-Object System.Windows.Forms.LinkLabel
                                                                      $lbl.DataBindings.DefaultDataSourceUpdateMode = 0
                                                                      $lbl.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
                                                                      $lbl.LinkColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
                                                                      $lbl.Location = New-Object System.Drawing.Point(980,(235 + 20 * $i))
                                                                      $lbl.Name = "machine_finder_fs_lbl_$i"
                                                                      $lbl.Size = New-Object System.Drawing.Size(300,16)
                                                                      $lbl.TabStop = $false
                                                                      $lbl.Text = "$($disk.DeviceID) $([math]::Round($disk.Size / [math]::pow(1024,3))) GB | free $([math]::Round($disk.FreeSpace / [math]::pow(1024,3))) GB"
                                                                      $str = ("explorer \\" + $machine.Guest.Hostname + "\$($disk.DeviceID[0])$")
                                                                      Write-Verbose "Attaching OnClick command: $str"
                                                                      $SCRIPT:filesystem_commands += $str
                                                                      $lbl.add_Click({ Invoke-Expression -Command "$($SCRIPT:filesystem_commands[([int]$this.name[-1])-48])" }) # I know..
                                                                      $main_form.Controls.Add($lbl)
                                                                      $SCRIPT:filesystem_links += $lbl
                                                                      Write-Verbose "Created filesystem link  $($lbl.Name) .."
                                                                    }
                                                                  else
                                                                    {
                                                                      Write-Verbose "Too many filesystems found, creating more link .."
                                                                      $lbl = New-Object System.Windows.Forms.LinkLabel
                                                                      $lbl.DataBindings.DefaultDataSourceUpdateMode = 0
                                                                      $lbl.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
                                                                      $lbl.LinkColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
                                                                      $lbl.Location = New-Object System.Drawing.Point(980,(235 + 20 * $i))
                                                                      $lbl.Name = "machine_finder_fs_lbl_$i"
                                                                      $lbl.Size = New-Object System.Drawing.Size(300,16)
                                                                      $lbl.TabStop = $false
                                                                      $lbl.Text = "[more..]"
                                                                      $lbl.add_Click({ ShowWinFilesystems })
                                                                      $main_form.Controls.Add($lbl)
                                                                      $SCRIPT:filesystem_links += $lbl
                                                                      Write-Verbose "Created more link  $($lbl.Name) .."
                                                                      break;
                                                                    }
                                                                  $i++
                                                                }
                                                            }
                                                        }

                                                    }
                                                }
                                              $SCRIPT:machine_finder_listBox_orig_selectedindex = $machine_finder_listbox.SelectedIndex
                                            }
        
        $user_finder_listbox_MouseDown = {
                                           #Event Argument: $_ = [System.Windows.Forms.MouseEventArgs]
                                           if ($_.Button -eq [Windows.Forms.MouseButtons]::Right) 
                                             { 
		                                       $user_finder_listbox.SelectedIndex = $user_finder_listbox.IndexFromPoint($_.X, $_.Y)
                                             }

                                           Write-Verbose "User finder listbox selected index: $($user_finder_listbox.SelectedIndex)"
                                           if ($user_finder_listbox.SelectedIndex -gt -1)
                                             {
                                               $user_copier_button.Enabled = $true;
                                               $sam = ($user_finder_listbox.SelectedItem -split " ")[0]
                                               $user = Get-ADUser -Identity $SAM -Properties *
                                               if ($user.LockedOut) 
                                                 { 
                                                   $accountlocked_label.Visible = $accountunlock_link.Visible = $true
                                                 } 
                                               else 
                                                 { 
                                                   $accountlocked_label.Visible = $accountunlock_link.Visible = $false
                                                 }
                                               if (-not $user.Enabled) { $accountdisabled_label.Visible = $true } else { $accountdisabled_label.Visible = $false }
                                               if ($user.PasswordExpired) { $passwordexpired_label.Visible = $true } else { $passwordexpired_label.Visible = $false }
                                               if ($user.ThumbnailPhoto)
                                                 {
                                                   if (-not (Test-Path "C:\Temp")) { mkdir C:\Temp }
                                                   $file = "C:\Temp\$($SAM)_$($(Get-Date -Format o | % {$_ -replace ":", "."})).jpg"
                                                   Write-Verbose "Creating file: $file"
                                                   $user.ThumbnailPhoto | Set-Content $file -Encoding byte -Force -Confirm:$false
                                                   $user_finder_picturebox.ImageLocation = $file
                                                   $user_finder_picturebox.Visible = $true
                                                 }
                                               else
                                                 {
                                                   $user_finder_picturebox.ImageLocation = $standard_user_photo
                                                 }
                                               $user_finder_picturebox.Visible = $true
                                             }
                                         }

        $user_finder_picturebox_OnHover = { 
                                            if ( $user_finder_picturebox.Visible -and ($user_finder_picturebox.ImageLocation -notmatch [regex]::escape($standard_user_photo)))
                                              {
                                                Write-Verbose "Creating big picturebox on the fly.."
                                                $user_finder_picturebox_big = New-Object System.Windows.Forms.PictureBox
                                                $user_finder_picturebox_big.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
                                                $user_finder_picturebox_big.Cursor = [System.Windows.Forms.Cursors]::No
                                                $user_finder_picturebox_big.DataBindings.DefaultDataSourceUpdateMode = 0
                                                $user_finder_picturebox_big.Location = New-Object System.Drawing.Size(665,55)
                                                $user_finder_picturebox_big.Name = "user_finder_picturebox_big"
                                                $user_finder_picturebox_big.Size = New-Object System.Drawing.Size(150,150)
                                                $user_finder_picturebox_big.SizeMode = 4  # "zoom" the picture to fill the box as best as possible
                                                $user_finder_picturebox_big.TabStop = $False
                                                $user_finder_picturebox_big.ImageLocation = $user_finder_picturebox.ImageLocation
                                                $user_finder_picturebox_big.add_MouseLeave($user_finder_picturebox_big_OnLeave)
                                                $main_form.Controls.Add($user_finder_picturebox_big)
                                                Write-Verbose "Hiding small picturebox.."
                                                $user_finder_picturebox.Hide()
                                                $SCRIPT:machine_finder_listbox_visibility_status = $machine_finder_listbox.Visible
                                                Write-Verbose "machine_finder_listbox_visibility_status: $machine_finder_listbox_visibility_status"
                                                $machine_finder_listbox.Visible = $false
                                                $SCRIPT:machine_finder_textbox_visibility_status = $machine_finder_textbox.Visible
                                                Write-Verbose "machine_finder_textbox_visibility_status: $machine_finder_textbox_visibility_status"
                                                $machine_finder_textbox.Visible = $false
                                                $SCRIPT:accountunlock_link_visibility_status = $accountunlock_link.Visible
                                                $accountunlock_link.Visible = $false
                                                $user_finder_picturebox_big.BringToFront()
                                              }
                                          }

        $user_finder_picturebox_big_OnLeave = { 
                                                Write-Verbose "Hiding and disposing big picturebox.."
                                                $this.Hide() 
                                                $this.Dispose()
                                                Write-Verbose "Restoring small picturebox.."
                                                $user_finder_picturebox.Show()
                                                $accountunlock_link.Visible = $accountunlock_link_visibility_status
                                                Write-Verbose "Restoring machine_finder_listbox_visibility_status to: $machine_finder_listbox_visibility_status"
                                                Write-Verbose "Restoring machine_finder_textbox_visibility_status to: $machine_finder_textbox_visibility_status"
                                                $machine_finder_listbox.Visible = $machine_finder_listbox_visibility_status
                                                $machine_finder_textbox.Visible = $machine_finder_textbox_visibility_status
                                              }

        $accountunlock_link_OnClick = { 
                                        $SAM = ($user_finder_listbox.SelectedItem -split " ")[0];
                                        Write-Verbose "Unlocking account $SAM.."
                                        Unlock-ADAccount -Identity $SAM -Confirm:$false
                                        Start-Sleep -Seconds 1
                                        $user = Get-ADUser -Identity $SAM -Properties *
                                        if ($user.LockedOut) 
                                          { 
                                            UI-MessageBox "Failed."
                                          } 
                                        else
                                          {
                                            $accountlocked_label.Visible = $false
                                            $accountunlock_link.Visible = $false
                                          }
                                      }

        $mailbox_finder_button_OnClick = { 
                                           if ($mailbox_finder_textbox.Text.Trim() -ne "") { FindExchangeObjects $mailbox_finder_textbox.Text.Trim() } 
                                         }

        function RandomString([int]$length) { ("abcdefghijklmnopqrstuvwxyz0123456789\£$%&/()=?^[]+*§#@-_:,;|'""".ToCharArray() | Sort {Get-Random})[0..($length-1)] -join '' } # w/ regex special chars

        function RandomChar { "abcdefghijklmnopqrstuvwxyz0123456789|!""£$%&/='ì^§°#@-_:,;".ToCharArray() | Get-Random <# no regex special chars #> }

        $ChangeLabels = {
                          $label_animation_timer.Interval = $label_animation_standard_interval
                          Write-Debug "Label animation: ticking... max label length: $SCRIPT:label_animation_max_label_length; max char changes: $label_animation_max_char_changes"
                          if ($SCRIPT:label_animation_char_position -le $SCRIPT:label_animation_max_label_length)
                            {
                              $main_form.Controls.GetEnumerator() | % { if (($_.Visible) -and ($_.getType().name -match 'label')) { $_.Text = RandomString($_.Text.Length) } }
                              $SCRIPT:label_animation_char_change_count++
                              if ($SCRIPT:label_animation_char_change_count -eq $label_animation_max_char_changes) 
                                { 
                                  $label_animation_timer.stop() 
                                  $label_animation_timer.Interval = $label_animation_standard_interval * 2
                                  $label_animation_timer.start() 
                                  $SCRIPT:label_animation_char_position++
                                  $SCRIPT:label_animation_char_change_count = 0 
                                  $main_form.Controls.GetEnumerator() | % { if (($_.Visible) -and ($_.getType().name -match 'label') -and ($_.Text.Length -lt $_.TabIndex)) { $_.Text = $_.Text + (RandomChar) } }
                               }
                            }
                          else
                            {
                              Start-Sleep -Milliseconds $label_animation_standard_sleep_duration
                              Write-Verbose "Stopping label animation timer and restoring original strings...$($original_texts.count) of them"
                              $label_animation_timer.stop() ; $i = 0
                              $main_form.Controls.GetEnumerator() | % { if ($_.getType().name -match 'label') { Write-Verbose "Restoring: $($original_texts[$i])"; $_.Text = $original_texts[$i]; $i++ } }
                            }
                        }

        $RestoreLabels = {
                           Write-Verbose "Restoring original strings...$($SCRIPT:original_texts.count) of them"
                           $i = 0
                           $main_form.Controls.GetEnumerator() | % { 
                                                                     if ($_.getType().name -match 'label') 
                                                                       { 
                                                                         Write-Verbose "Restoring: $($SCRIPT:original_texts[$i])"; 
                                                                         $_.Text = $SCRIPT:original_texts[$i]; $i++ 
                                                                       } 
                                                                   }
                           $label_animation_timer_simple.Stop()
                         }

        $main_form_OnLoad = { 
                              Write-Verbose "Displaying tray balloon tip.."
                              $NotifyIcon.ShowBalloonTip(30000,"Bitman's PowerShell Toolbox","Ready!",[system.windows.forms.ToolTipIcon]"Info")
                              $main_form.WindowState = $InitialFormWindowState # force the initial state of the form

                              if ($onload_animations)
                                {
                                  if ($onload_animation_type -eq 'simple')
                                    {
                                      $label_animation_timer_simple.Interval = $label_animation_simple_sleep_duration
                                      $label_animation_timer_simple.add_Tick($RestoreLabels)
                                      $SCRIPT:original_texts = New-Object System.Collections.Arraylist
                                      $main_form.Controls.GetEnumerator() | % { if ($_.getType().name -match 'label') { $SCRIPT:original_texts.Add($_.Text); } }
                                      Write-Verbose "Label animation: form controls count: $($main_form.Controls.count); count of saved texts: $($SCRIPT:original_texts.count) "
                                      $main_form.Controls.GetEnumerator() | % { if ($_.getType().name -match 'label') { $_.Text = RandomString($_.Text.Length) } }
                                      Write-Verbose "Waiting for $label_animation_simple_sleep_duration milliseconds"
                                      $label_animation_timer_simple.Start()
                                    }
                                  else
                                    {
                                      $label_animation_timer.Interval = $label_animation_standard_interval
                                      $label_animation_timer.add_Tick($ChangeLabels)
                                      $SCRIPT:original_texts = New-Object System.Collections.Arraylist
                                      $main_form.Controls.GetEnumerator() | % { if ($_.getType().name -match 'label') { $original_texts.Add($_.Text); $_.TabIndex = $_.Text.Trim().Length; $_.Text = " " } }
                                      Write-Verbose "Label animation: form controls count: $($main_form.Controls.count); count of saved texts: $($original_texts.count) "
                                      $original_texts | % { 
                                                            if ($_.Length -gt $SCRIPT:label_animation_max_label_length) 
                                                              { 
                                                                $SCRIPT:label_animation_max_label_length = ($_.length - $SCRIPT:label_animation_max_label_length_reduction) 
                                                              } 
                                                          }
                                      Write-Verbose "Label animation: max label length: $($SCRIPT:label_animation_max_label_length); starting label animation timer."
                                      $label_animation_timer.start()
                                    }
                                }
                            }

        $main_form_OnClose = { 
                               Write-Verbose "Closing tray icon.."
                               $NotifyIcon.Visible = $false;
                             }
        
        #region form controls
        Write-Verbose "Setting main form parameters, background image, name, caption.."
        $main_form.BackgroundImage = [System.Drawing.Image]::FromFile($standard_background_image)
        $main_form.BackgroundImageLayout = 3
        $main_form.ClientSize = New-Object System.Drawing.Size(1125,600)
        $main_form.DataBindings.DefaultDataSourceUpdateMode = 0
        $main_form.FormBorderStyle = 5
        $main_form.StartPosition = 1 # "CenterScreen"
        $main_form.ShowInTaskbar = $false
        $main_form.Name = "main_form"
        $main_form.Text = "Bitman's Toolbox - I know what you did last session :)"
        # $main_form.Add_KeyDown({if ($_.KeyCode -eq "Escape") {$main_form.Close()}}) # useless: no way to have the actual form in focus
        
        Write-Verbose "Displaying tray icon.."
        $NotifyIcon.Icon =  $icon1
        $NotifyIcon.Visible = $True
        Write-Verbose "Creating tray context menu.."
        $Tray_Menu_Item_Show.Name = 'tray_menu_item_show'
        $Tray_Menu_Item_Show.Text = 'Show'
        $Tray_Menu_Item_Show.add_Click({ Write-Verbose "Restoring main window state.."; $main_form.WindowState = "normal"; $main_form.BringToFront() | Out-Null })     
        $Tray_Menu_Item_Exit.Name = 'Tray_Menu_Item_Exit'
        $Tray_Menu_Item_Exit.Text = 'Exit'
        $Tray_Menu_Item_Exit.add_Click({ $main_form.Close() })
        $NotifyIcon.ContextMenu = $Tray_ContextMenu
        $Tray_ContextMenu.MenuItems.Add($Tray_Menu_Item_Show) | Out-Null
        $Tray_ContextMenu.MenuItems.Add($Tray_Menu_Item_Exit) | Out-Null
        $NotifyIcon.Text = "Bitman's PowerShell Toolbox: waiting for commands"

        Write-Verbose "Creating Main tools big label.."
        $tool_selection_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $tool_selection_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $tool_selection_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $tool_selection_label.Font = New-Object System.Drawing.Font("Gisha",15.75,1,3,0)
        $tool_selection_label.Location = New-Object System.Drawing.Size(12,18)
        $tool_selection_label.Name = "tool_selection_label"
        $tool_selection_label.Size = New-Object System.Drawing.Size(260,30)
        $tool_selection_label.TabIndex = 3
        $tool_selection_label.Text = "Main tools:"
        $main_form.Controls.Add($tool_selection_label)
    
        Write-Verbose "Creating Destination label.."
        $label3.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $label3.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $label3.DataBindings.DefaultDataSourceUpdateMode = 0
        $label3.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $label3.Location = New-Object System.Drawing.Point(8,197)
        $label3.Name = "label3"
        $label3.Size = New-Object System.Drawing.Size(90,20)
        $label3.TabIndex = 7
        $label3.Text = " Destination:"
        $label3.TextAlign = 16
        $label3.BorderStyle = 0
        $main_form.Controls.Add($label3)
        
        Write-Verbose "Creating Source label.."
        $label2.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $label2.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $label2.DataBindings.DefaultDataSourceUpdateMode = 0
        $label2.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $label2.Location = New-Object System.Drawing.Point(8,168)
        $label2.Name = "label2"
        $label2.Size = New-Object System.Drawing.Size(90,20)
        $label2.TabIndex = 6
        $label2.Text = " Source:"
        $label2.TextAlign = 16
        $label2.BorderStyle = 0
        $main_form.Controls.Add($label2)
        
        Write-Verbose "Creating destination input box.."
        $dest_textbox.DataBindings.DefaultDataSourceUpdateMode = 0
        $dest_textbox.Font = $standard_font
        $dest_textbox.Location = New-Object System.Drawing.Point(99,200)
        $dest_textbox.Name = "dest_textbox"
        $dest_textbox.Size = New-Object System.Drawing.Size(181,20)
        $dest_textbox.TabIndex = 5
        $main_form.Controls.Add($dest_textbox)
        
        Write-Verbose "Creating source input box.."
        $source_textbox.DataBindings.DefaultDataSourceUpdateMode = 0
        $source_textbox.Font = $standard_font
        $source_textbox.Location = New-Object System.Drawing.Point(99,169)
        $source_textbox.Name = "source_textbox"
        $source_textbox.Size = New-Object System.Drawing.Size(181,20)
        $source_textbox.TabIndex = 4
        $main_form.Controls.Add($source_textbox)
        
        Write-Verbose "Creating Ugo 'box button.."
        $Ugo_box_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $Ugo_box_button.Font = New-Object System.Drawing.Font("Gisha",9.75,1,3,0)
        $Ugo_box_button.Location = New-Object System.Drawing.Point(12,53)
        $Ugo_box_button.Name = "Ugo_box_button"
        $Ugo_box_button.Size = New-Object System.Drawing.Size(268,48)
        $Ugo_box_button.TabIndex = 2
        $Ugo_box_button.Text = "Ugo 'box`n(not updated after 23/12/2015)"
        $Ugo_box_button.UseVisualStyleBackColor = $True
        $Ugo_box_button.add_Click($Ugo_box_button_OnClick)
        $main_form.Controls.Add($Ugo_box_button)
    
        Write-Verbose "Creating Compare users button.."
        $compareusers_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $compareusers_button.Font = New-Object System.Drawing.Font("Gisha",9.75,1,3,0)
        $compareusers_button.Location = New-Object System.Drawing.Size(12,112)
        $compareusers_button.Name = "compareusers_button"
        $compareusers_button.Size = New-Object System.Drawing.Size(126,48)
        $compareusers_button.TabIndex = 0
        $compareusers_button.Text = "Compare users,`ncopy groups"
        $compareusers_button.UseVisualStyleBackColor = $True
        $compareusers_button.add_Click($compareusers_button_OnClick)
        $main_form.Controls.Add($compareusers_button)

        Write-Verbose "Creating Compare groups button.."
        $comparegroups_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $comparegroups_button.Font = New-Object System.Drawing.Font("Gisha",9.75,1,3,0)
        $comparegroups_button.Location = New-Object System.Drawing.Point(153,112)
        $comparegroups_button.Name = "comparegroups_button"
        $comparegroups_button.Size = New-Object System.Drawing.Size(127,48)
        $comparegroups_button.TabIndex = 34
        $comparegroups_button.Text = "Compare groups,`ncopy users"
        $comparegroups_button.UseVisualStyleBackColor = $True
        $comparegroups_button.add_Click($comparegroups_button_OnClick)
        $main_form.Controls.Add($comparegroups_button)

        #region Run omnibox
        Write-Verbose "Creating run label.."
        $run_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $run_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $run_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $run_label.Font = New-Object System.Drawing.Font("Gisha",15.75,1,3,0)
        $run_label.Location = New-Object System.Drawing.Point(12,245)
        $run_label.Name = "run_label"
        $run_label.Size = New-Object System.Drawing.Size(50,30)
        $run_label.TabIndex = 59
        $run_label.Text = "Run"
        $run_label.BorderStyle = 0
        $main_form.Controls.Add($run_label)

        Write-Verbose "Creating CMD link.."
        $runCMD_link_OnClick = { Start-Job -ScriptBlock { cmd /c start cmd } }
        $runCMD_link.DataBindings.DefaultDataSourceUpdateMode = 0
        $runCMD_link.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $runCMD_link.LinkColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $runCMD_link.Location = New-Object System.Drawing.Point(($run_label.Location.X + $run_label.Size.Width - 5), ($run_label.Location.Y + 2))
        $runCMD_link.Name = "runCMD_link"
        $runCMD_link.Font = New-Object System.Drawing.Font("Gisha",14,1,3,0)
        $runCMD_link.Size = New-Object System.Drawing.Size(75,30)
        $runCMD_link.TabIndex = 73
        $runCMD_link.TabStop = $True
        $runCMD_link.BorderStyle = 0
        $runCMD_link.Text = "[CMD]"
        $runCMD_link.add_Click($runCMD_link_OnClick)
        $main_form.Controls.Add($runCMD_link)
        $runCMD_link.BringToFront()

        Write-Verbose "Creating : label.."
        $colon_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $colon_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $colon_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $colon_label.Font = New-Object System.Drawing.Font("Gisha",15.75,1,3,0)
        $colon_label.Location = New-Object System.Drawing.Point(($runCMD_link.Location.X + $runCMD_link.Size.Width - 15),$run_label.Location.Y)
        $colon_label.Name = "colon_label"
        $colon_label.Size = New-Object System.Drawing.Size(50,30)
        $colon_label.TabIndex = 74
        $colon_label.Text = ":"
        $main_form.Controls.Add($colon_label)
        $colon_label.BringToFront()

        Write-Verbose "Creating run input box.."
        $run_textbox.DataBindings.DefaultDataSourceUpdateMode = 0
        $run_textbox.Font = $standard_font
        $run_textbox.Location = New-Object System.Drawing.Size(14,280)
        $run_textbox.Name = "run_textbox"
        $run_textbox.Size = New-Object System.Drawing.Size(203,20)
        $run_textbox.TabIndex = 60
        $run_textbox.Add_KeyDown({if ($_.KeyCode -eq "Enter") { $run_button.PerformClick() }})
        $main_form.Controls.Add($run_textbox)

        Write-Verbose "Creating run GO button.."
        $run_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $run_button.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $run_button.Location = New-Object System.Drawing.Point(233,280)
        $run_button.Name = "run_button"
        $run_button.Size = New-Object System.Drawing.Size(49,23)
        $run_button.TabIndex = 61
        $run_button.Text = "GO"
        $run_button.UseVisualStyleBackColor = $True
        $run_button.add_Click($run_button_OnClick)
        $main_form.Controls.Add($run_button)

        Write-Verbose "Creating run WITH PATH button.."
        $withpath_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $withpath_button.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $withpath_button.Location = New-Object System.Drawing.Point(295,280)
        $withpath_button.Name = "withpath_button"
        $withpath_button.Size = New-Object System.Drawing.Size(100,23)
        $withpath_button.TabIndex = 75
        $withpath_button.Text = "WITH PATH"
        $withpath_button.UseVisualStyleBackColor = $True
        $withpath_button.add_Click({ $withpath_button_ContextMenu.Show([System.Windows.Forms.Control]$withpath_button, (New-Object System.Drawing.Point(0,0))) })
        $main_form.Controls.Add($withpath_button)

        Write-Verbose "Creating a small context menu for the WITH PATH button.."
        $withpath_button_ContextMenu = New-Object System.Windows.Forms.ContextMenu

        $withpath_button_MenuItem0 = New-Object System.Windows.Forms.MenuItem
        $withpath_button_MenuItem0.Name = 'withpath_button_menu_item0'
        $withpath_button_MenuItem0.Text = 'View permissions'
        $withpath_button_MenuItem0.add_Click({ if ($run_textbox.Text) { ShowAcl $run_textbox.Text.ToString().Trim() } else { UI-MessageBox "Input a path please." } })
        $withpath_button_ContextMenu.MenuItems.Add($withpath_button_MenuItem0) | Out-Null

        $withpath_button_MenuItem1 = New-Object System.Windows.Forms.MenuItem
        $withpath_button_MenuItem1.Name = 'withpath_button_MenuItem1'
        $withpath_button_MenuItem1.Text = 'View permissions for selected user'
        $withpath_button_MenuItem1.add_Click({ 
                                               if ($run_textbox.Text) 
                                                 { 
                                                   if ($user_finder_listbox.SelectedIndex -gt -1)
                                                     {
                                                       ShowAcl $run_textbox.Text.ToString().Trim() $(($user_finder_listbox.SelectedItem -split " ")[0]) 
                                                     }
                                                   else
                                                     {
                                                       UI-MessageBox "Select an account in the user finder please."
                                                     }
                                                 }
                                                else
                                                 {
                                                   UI-MessageBox "Input a path please."
                                                 }
                                             })
        $withpath_button_ContextMenu.MenuItems.Add($withpath_button_MenuItem1) | Out-Null
        
        Write-Verbose "Attaching the user WITH PATH button context menu.."
        $withpath_button.ContextMenu = $ContextMenu
        #endregion Run omnibox

        #region CLI tools
        Write-Verbose "Creating CLI tools big label.."
        $label4.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $label4.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $label4.DataBindings.DefaultDataSourceUpdateMode = 0
        $label4.Font = New-Object System.Drawing.Font("Gisha",15.75,1,3,0)
        $label4.Location = New-Object System.Drawing.Point(12,323)
        $label4.Name = "label4"
        $label4.Size = New-Object System.Drawing.Size(240,30)
        $label4.TabIndex = 8
        $label4.Text = "CLI tools ("
        $label4.BorderStyle = 0
        $main_form.Controls.Add($label4)

        Write-Verbose "Creating verbose checkbox.."
        $verbose_checkbox.DataBindings.DefaultDataSourceUpdateMode = 0
        $verbose_checkbox.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $verbose_checkbox.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $verbose_checkbox.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $verbose_checkbox.Location = New-Object System.Drawing.Point(124,325)
        $verbose_checkbox.Name = "verbose_checkbox"
        $verbose_checkbox.Size = New-Object System.Drawing.Size(85,24)
        $verbose_checkbox.TabIndex = 26
        $verbose_checkbox.Text = "verbose -"
        $verbose_checkbox.Checked = $true
        $main_form.Controls.Add($verbose_checkbox)
        $verbose_checkbox.BringToFront()

        Write-Verbose "Creating debug checkbox.."
        $debug_checkbox.DataBindings.DefaultDataSourceUpdateMode = 0
        $debug_checkbox.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $debug_checkbox.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $debug_checkbox.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $debug_checkbox.Location = New-Object System.Drawing.Point(199,325)
        $debug_checkbox.Name = "debug_checkbox"
        $debug_checkbox.Size = New-Object System.Drawing.Size(100,24)
        $debug_checkbox.TabIndex = 27
        $debug_checkbox.Text = "debug"
        $debug_checkbox.UseVisualStyleBackColor = $True
        $main_form.Controls.Add($debug_checkbox)
        $debug_checkbox.BringToFront()

        Write-Verbose "Creating ) label.."
        $parens_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $parens_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $parens_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $parens_label.Font = New-Object System.Drawing.Font("Gisha",15.75,1,3,0)
        $parens_label.Location = New-Object System.Drawing.Size(255,323)
        $parens_label.Name = "parens_label"
        $parens_label.Size = New-Object System.Drawing.Size(25,30)
        $parens_label.TabStop = $false
        $parens_label.Text = "):"
        $main_form.Controls.Add($parens_label)
        $parens_label.BringToFront()

        Write-Verbose "Creating AD tools button.."
        $AD_tools_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $AD_tools_button.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $AD_tools_button.Location = New-Object System.Drawing.Size(12,445)
        $AD_tools_button.Name = "AD_tools_button"
        $AD_tools_button.Size = New-Object System.Drawing.Size(269,26)
        $AD_tools_button.TabIndex = 17
        $AD_tools_button.Text = "GO"
        $AD_tools_button.UseVisualStyleBackColor = $True
        $AD_tools_button.add_Click($AD_tools_button_OnClick)
        $main_form.Controls.Add($AD_tools_button)
    
        Write-Verbose "Creating AD tools params listbox.."
        $AD_tools_params_listbox.DataBindings.DefaultDataSourceUpdateMode = 0
        $AD_tools_params_listbox.Font = $standard_font
        $AD_tools_params_listbox.Location = New-Object System.Drawing.Size(75,421)
        $AD_tools_params_listbox.Name = "AD_tools_params_listbox"
        $AD_tools_params_listbox.Size = New-Object System.Drawing.Size(185,20)
        $AD_tools_params_listbox.TabIndex = 14
        $AD_tools_params_listbox.Add_KeyDown({if ($_.KeyCode -eq "Enter") { $AD_tools_button.PerformClick() }})
        $main_form.Controls.Add($AD_tools_params_listbox)
    
        Write-Verbose "Creating AD tools params label.."
        $label7.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $label7.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $label7.DataBindings.DefaultDataSourceUpdateMode = 0
        $label7.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $label7.Location = New-Object System.Drawing.Size(12,420)
        $label7.Name = "label7"
        $label7.Size = New-Object System.Drawing.Size(60,18)
        $label7.TabIndex = 13
        $label7.Text = "Params:"
        $main_form.Controls.Add($label7)
        
        Write-Verbose "Creating Active Directory big label.."
        $label5.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $label5.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $label5.DataBindings.DefaultDataSourceUpdateMode = 0
        $label5.Font = New-Object System.Drawing.Font("Gisha",11.25,1,3,0)
        $label5.Location = New-Object System.Drawing.Size(12,361)
        $label5.Name = "label5"
        $label5.Size = New-Object System.Drawing.Size(290,28)
        $label5.TabIndex = 10
        $label5.Text = "AD, Exchange, vSphere, network"
        $main_form.Controls.Add($label5)
        
        Write-Verbose "Creating Active Directory params ComboBox.."
        $AD_tools_combobox.DataBindings.DefaultDataSourceUpdateMode = 0
        $AD_tools_combobox.Font = $standard_font
        $AD_tools_combobox.FormattingEnabled = $True
        $AD_tools_combobox.Location =  New-Object System.Drawing.Size(12,392)
        $AD_tools_combobox.Name = "AD_tools_combobox"
        $AD_tools_combobox.Size =  New-Object System.Drawing.Size(268,21)
        $AD_tools_combobox.TabIndex = 9
        $AD_tools_combobox.AutoCompleteMode = 1     # "Suggest"
        $AD_tools_combobox.AutoCompleteSource = 256 # ListItems
        Write-Verbose "Populating AD ComboBox with AD-* function names.."
        ForEach ($f in $functions) { if ($f -match "AD-|DNS-|Net-|Exch7-|VMw-") { $AD_tools_combobox.Items.Add($f) | Out-Null } }
        $AD_tools_combobox.SelectedIndex = 0
        $main_form.Controls.Add($AD_tools_combobox)

        $misc_tools_y_baseline = 484
        $misc_tools_x_baseline = 12
        
        Write-Verbose "Creating Misc tools button.."
        $misc_tools_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $misc_tools_button.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $misc_tools_button.Location = New-Object System.Drawing.Size($misc_tools_x_baseline,568)
        $misc_tools_button.Name = "misc_tools_button"
        $misc_tools_button.Size = New-Object System.Drawing.Size(269,26)
        $misc_tools_button.TabIndex = 44
        $misc_tools_button.Text = "GO"
        $misc_tools_button.UseVisualStyleBackColor = $True
        $misc_tools_button.add_Click($misc_tools_button_OnClick)
        $main_form.Controls.Add($misc_tools_button)
    
        Write-Verbose "Creating Misc tools params label.."
        $misc_tools_params_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $misc_tools_params_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $misc_tools_params_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $misc_tools_params_label.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $misc_tools_params_label.Location = New-Object System.Drawing.Size($misc_tools_x_baseline,543)
        $misc_tools_params_label.Name = "misc_tools_params_label"
        $misc_tools_params_label.Size = New-Object System.Drawing.Size(60,18)
        $misc_tools_params_label.TabIndex = 45
        $misc_tools_params_label.Text = "Params:"
        $main_form.Controls.Add($misc_tools_params_label)

        Write-Verbose "Creating Misc tools params listbox.."
        $misc_tools_params_listbox.DataBindings.DefaultDataSourceUpdateMode = 0
        $misc_tools_params_listbox.Font = $standard_font
        $misc_tools_params_listbox.Location = New-Object System.Drawing.Size(($misc_tools_x_baseline + $misc_tools_params_label.size.width),544)
        $misc_tools_params_listbox.Name = "misc_tools_params_listbox"
        $misc_tools_params_listbox.Size = New-Object System.Drawing.Size(185,20)
        $misc_tools_params_listbox.TabIndex = 46
        $misc_tools_params_listbox.Add_KeyDown({if ($_.KeyCode -eq "Enter") { $misc_tools_params_listbox.PerformClick() }})
        $main_form.Controls.Add($misc_tools_params_listbox)
        
        Write-Verbose "Creating Misc tools params ComboBox.."
        $misc_tools_combobox.DataBindings.DefaultDataSourceUpdateMode = 0
        $misc_tools_combobox.Font = $standard_font
        $misc_tools_combobox.FormattingEnabled = $True
        $misc_tools_combobox.Location = New-Object System.Drawing.Size($misc_tools_x_baseline,515)
        $misc_tools_combobox.Name = "misc_tools_combobox"
        $misc_tools_combobox.Size = New-Object System.Drawing.Size(268,21)
        $misc_tools_combobox.TabIndex = 47
        $misc_tools_combobox.AutoCompleteMode = 1     # "Suggest"
        $misc_tools_combobox.AutoCompleteSource = 256 # ListItems
        Write-Verbose "Populating Misc ComboBox with misc function names.."
        ForEach ($f in $functions) { if ($f -match "Misc-") { $misc_tools_combobox.Items.Add($f) | Out-Null } }
        $misc_tools_combobox.SelectedIndex = 1
        $main_form.Controls.Add($misc_tools_combobox)

        Write-Verbose "Creating AD tools help link.."
        $AD_tools_help_link.DataBindings.DefaultDataSourceUpdateMode = 0
        $AD_tools_help_link.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $AD_tools_help_link.LinkColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $AD_tools_help_link.Location = New-Object System.Drawing.Point(270,423)
        $AD_tools_help_link.Name = "AD_tools_help_link"
        $AD_tools_help_link.Size = New-Object System.Drawing.Size(15,16)
        $AD_tools_help_link.TabIndex = 30
        $AD_tools_help_link.TabStop = $True
        $AD_tools_help_link.Text = "?"
        $AD_tools_help_link.add_Click($AD_tools_help_link_OnClick)
        $main_form.Controls.Add($AD_tools_help_link)

        Write-Verbose "Creating Misc tools help link.."
        $misc_tools_help_link.DataBindings.DefaultDataSourceUpdateMode = 0
        $misc_tools_help_link.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $misc_tools_help_link.LinkColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $misc_tools_help_link.Location = New-Object System.Drawing.Point(($misc_tools_x_baseline + $misc_tools_params_label.size.width + $misc_tools_params_listbox.size.width + $standard_x_whitespace), 546)
        $misc_tools_help_link.Name = "misc_tools_help_link"
        $misc_tools_help_link.Size = New-Object System.Drawing.Size(15,16)
        $misc_tools_help_link.TabIndex = 49
        $misc_tools_help_link.TabStop = $True
        $misc_tools_help_link.Text = "?"
        $misc_tools_help_link.visible = $true
        $misc_tools_help_link.add_Click($misc_tools_help_link_OnClick)
        $main_form.Controls.Add($misc_tools_help_link)

        Write-Verbose "Creating Misc tools big label.."
        $label13.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $label13.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $label13.DataBindings.DefaultDataSourceUpdateMode = 0
        $label13.Font = New-Object System.Drawing.Font("Gisha",11.25,1,3,0)
        $label13.Location = New-Object System.Drawing.Point($misc_tools_x_baseline, 484)
        $label13.Name = "label13"
        $label13.Size = New-Object System.Drawing.Size(260,28)
        $label13.TabIndex = 48
        $label13.Text = "Miscellaneous"
        $main_form.Controls.Add($label13)
        #endregion CLI tools

        #region External tools
        $ext_x_base = 660
        $ext_y_base = 425 + 27

        Write-Verbose "Creating External tools label.."
        $external_tools_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $external_tools_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $external_tools_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $external_tools_label.Font = New-Object System.Drawing.Font("Gisha",15.75,1,3,0)
        $external_tools_label.Location = New-Object System.Drawing.Point($ext_x_base,$ext_y_base) #765, 245
        $external_tools_label.Name = "external_tools_label"
        $external_tools_label.Size = New-Object System.Drawing.Size(155,30)
        $external_tools_label.TabIndex = 63
        $external_tools_label.Text = "External tools:"
        $main_form.Controls.Add($external_tools_label)

        Write-Verbose "Creating External tools DSA.MSC button.."
        $external_tools_dsamsc_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $external_tools_dsamsc_button.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $external_tools_dsamsc_button.Location = New-Object System.Drawing.Point(($ext_x_base + 2),($ext_y_base + 35))
        $external_tools_dsamsc_button.Name = "external_tools_dsamsc_button"
        $external_tools_dsamsc_button.Size = New-Object System.Drawing.Size(80,23)
        $external_tools_dsamsc_button.TabIndex = 64
        $external_tools_dsamsc_button.Text = "DSA.MSC"
        $external_tools_dsamsc_button.UseVisualStyleBackColor = $True
        $external_tools_dsamsc_button.add_Click({ Invoke-Expression -Command "dsa.msc" })
        $main_form.Controls.Add($external_tools_dsamsc_button)

        Write-Verbose "Creating External tools GPMC.MSC button.."
        $external_tools_gpmcmsc_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $external_tools_gpmcmsc_button.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $external_tools_gpmcmsc_button.Location = New-Object System.Drawing.Point(($ext_x_base + 94),($ext_y_base + 35))
        $external_tools_gpmcmsc_button.Name = "external_tools_gpmcmsc_button"
        $external_tools_gpmcmsc_button.Size = New-Object System.Drawing.Size(83,23)
        $external_tools_gpmcmsc_button.TabIndex = 65
        $external_tools_gpmcmsc_button.Text = "GPMC.MSC"
        $external_tools_gpmcmsc_button.UseVisualStyleBackColor = $True
        $external_tools_gpmcmsc_button.add_Click({ Invoke-Expression -Command "gpmc.msc" })
        $main_form.Controls.Add($external_tools_gpmcmsc_button)

        Write-Verbose "Creating External tools COMPMGMT.MSC button.."
        $external_tools_compmgmt_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $external_tools_compmgmt_button.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $external_tools_compmgmt_button.Location = New-Object System.Drawing.Point(($ext_x_base + 188),($ext_y_base + 35))
        $external_tools_compmgmt_button.Name = "external_tools_compmgmt_button"
        $external_tools_compmgmt_button.Size = New-Object System.Drawing.Size(125,23)
        $external_tools_compmgmt_button.TabIndex = 66
        $external_tools_compmgmt_button.Text = "COMPMGMT.MSC"
        $external_tools_compmgmt_button.UseVisualStyleBackColor = $True
        $external_tools_compmgmt_button.add_Click({ Invoke-Expression -Command "compmgmt.msc" })
        $main_form.Controls.Add($external_tools_compmgmt_button)

        Write-Verbose "Creating External tools EXCHANGE.MSC button.."
        $external_tools_exchangemsc_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $external_tools_exchangemsc_button.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $external_tools_exchangemsc_button.Location = New-Object System.Drawing.Point(($ext_x_base + 188),($ext_y_base + 68))
        $external_tools_exchangemsc_button.Name = "external_tools_exchangemsc_button"
        $external_tools_exchangemsc_button.Size = New-Object System.Drawing.Size(125,23)
        $external_tools_exchangemsc_button.TabIndex = 67
        $external_tools_exchangemsc_button.Text = "EXCHANGE.MSC"
        $external_tools_exchangemsc_button.UseVisualStyleBackColor = $True
        $external_tools_exchangemsc_button.add_Click({ & "Exchange Management Console.msc" })
        $main_form.Controls.Add($external_tools_exchangemsc_button)

        Write-Verbose "Creating External tools DNS.MSC button.."
        $external_tools_dnsmsc_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $external_tools_dnsmsc_button.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $external_tools_dnsmsc_button.Location = New-Object System.Drawing.Point(($ext_x_base + 94),($ext_y_base + 68))
        $external_tools_dnsmsc_button.Name = "external_tools_dnsmsc_button"
        $external_tools_dnsmsc_button.Size = New-Object System.Drawing.Size(83,23)
        $external_tools_dnsmsc_button.TabIndex = 68
        $external_tools_dnsmsc_button.Text = "DNS.MSC"
        $external_tools_dnsmsc_button.UseVisualStyleBackColor = $True
        $external_tools_dnsmsc_button.add_Click({ Invoke-Expression -Command "dnsmgmt.msc" })
        $main_form.Controls.Add($external_tools_dnsmsc_button)

        Write-Verbose "Creating External tools RDP.MSC button.."
        $external_tools_rdpmsc_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $external_tools_rdpmsc_button.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $external_tools_rdpmsc_button.Location = New-Object System.Drawing.Point(($ext_x_base + 2),($ext_y_base + 68))
        $external_tools_rdpmsc_button.Name = "external_tools_rdpmsc_button"
        $external_tools_rdpmsc_button.Size = New-Object System.Drawing.Size(80,23)
        $external_tools_rdpmsc_button.TabIndex = 69
        $external_tools_rdpmsc_button.Text = "RDP.MSC"
        $external_tools_rdpmsc_button.UseVisualStyleBackColor = $True
        $external_tools_rdpmsc_button.add_Click({ Invoke-Expression -Command "tsadmin.msc" })
        $main_form.Controls.Add($external_tools_rdpmsc_button)
        #endregion External tools

        #region USER FINDER
        Write-Verbose "Creating user finder label.."
        $user_finder_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $user_finder_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $user_finder_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $user_finder_label.Font = New-Object System.Drawing.Font("Gisha",15.75,1,3,0)
        $user_finder_label.Location = New-Object System.Drawing.Size(305,18)
        $user_finder_label.Name = "user_finder_label"
        $user_finder_label.Size = New-Object System.Drawing.Size(200,30)
        $user_finder_label.TabIndex = 24
        $user_finder_label.Text = "User finder:"
        $main_form.Controls.Add($user_finder_label)

        Write-Verbose "Creating user finder input box.."
        $user_finder_textbox.DataBindings.DefaultDataSourceUpdateMode = 0
        $user_finder_textbox.Font = $standard_font
        $user_finder_textbox.Location = New-Object System.Drawing.Size(305,55)
        $user_finder_textbox.Name = "user_finder_textbox"
        $user_finder_textbox.Size = New-Object System.Drawing.Size(120,20)
        $user_finder_textbox.TabIndex = 25
        $user_finder_textbox.Add_KeyDown({if ($_.KeyCode -eq "Enter") { $user_finder_button.PerformClick() }})
        $main_form.Controls.Add($user_finder_textbox)

        Write-Verbose "Creating user finder GO button.."
        $user_finder_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $user_finder_button.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $user_finder_button.Location = New-Object System.Drawing.Size(440,55)
        $user_finder_button.Name = "user_finder_button"
        $user_finder_button.Size = New-Object System.Drawing.Size(49,23)
        $user_finder_button.TabIndex = 28
        $user_finder_button.Text = "GO"
        $user_finder_button.UseVisualStyleBackColor = $True
        $user_finder_button.add_Click($user_finder_button_OnClick)
        $main_form.Controls.Add($user_finder_button)

        Write-Verbose "Creating user finder results listbox.."
        $user_finder_listBox.Location = New-Object System.Drawing.Size(305,90) 
        $user_finder_listBox.Size = New-Object System.Drawing.Size(330, 137)
        $user_finder_listBox.Font = $standard_font
        $user_finder_listBox.SelectionMode = "One"
        $user_finder_listBox.Visible = $false
        $user_finder_listBox.Add_MouseDown($user_finder_listbox_MouseDown)
        
        Write-Verbose "Creating a small context menu for the user finder listbox.."
        $ContextMenu = New-Object System.Windows.Forms.ContextMenu

        $MenuItem0 = New-Object System.Windows.Forms.MenuItem
        $MenuItem0.Name = 'user_finder_menu_item0'
        $MenuItem0.Text = 'Enable/disable'
        $MenuItem0.add_Click({ if ($user_finder_listbox.SelectedIndex -gt -1) {ToggleAccount $(($user_finder_listbox.SelectedItem -split " ")[0])}})
        $ContextMenu.MenuItems.Add($MenuItem0) | Out-Null

        $MenuItem1 = New-Object System.Windows.Forms.MenuItem
        $MenuItem1.Name = 'user_finder_menu_item1'
        $MenuItem1.Text = 'Reset password'
        $MenuItem1.add_Click({ if ($user_finder_listbox.SelectedIndex -gt -1) {ResetUserPassword $(($user_finder_listbox.SelectedItem -split " ")[0])}})
        $ContextMenu.MenuItems.Add($MenuItem1) | Out-Null

        $reset_password_MenuItem1 = New-Object System.Windows.Forms.MenuItem
        $reset_password_MenuItem1.Name = 'reset_password_MenuItem1'
        $reset_password_MenuItem1.Text = 'Mediobanca2015'
        $reset_password_MenuItem1.add_Click({ if ($user_finder_listbox.SelectedIndex -gt -1) {ResetUserPassword $(($user_finder_listbox.SelectedItem -split " ")[0]) 'Mediobanca2015'}})

        $reset_password_MenuItem2 = New-Object System.Windows.Forms.MenuItem
        $reset_password_MenuItem2.Name = 'reset_password_MenuItem2'
        $reset_password_MenuItem2.Text = 'Mediobanca01'
        $reset_password_MenuItem2.add_Click({ if ($user_finder_listbox.SelectedIndex -gt -1) {ResetUserPassword $(($user_finder_listbox.SelectedItem -split " ")[0]) 'Mediobanca01'}})

        $reset_password_MenuItem3 = New-Object System.Windows.Forms.MenuItem
        $reset_password_MenuItem3.Name = 'reset_password_MenuItem'
        $reset_password_MenuItem3.Text = 'CheBanca2015'
        $reset_password_MenuItem3.add_Click({ if ($user_finder_listbox.SelectedIndex -gt -1) {ResetUserPassword $(($user_finder_listbox.SelectedItem -split " ")[0]) 'CheBanca2015'}})

        $reset_password_MenuItem4 = New-Object System.Windows.Forms.MenuItem
        $reset_password_MenuItem4.Name = 'reset_password_MenuItem'
        $reset_password_MenuItem4.Text = 'CheBanca!01'
        $reset_password_MenuItem4.add_Click({ if ($user_finder_listbox.SelectedIndex -gt -1) {ResetUserPassword $(($user_finder_listbox.SelectedItem -split " ")[0]) "CheBanca!01"}})

        $reset_password_MenuItem5 = New-Object System.Windows.Forms.MenuItem
        $reset_password_MenuItem5.Name = 'reset_password_MenuItem'
        $reset_password_MenuItem5.Text = 'P3pp1n13ll0'
        $reset_password_MenuItem5.add_Click({ if ($user_finder_listbox.SelectedIndex -gt -1) {ResetUserPassword $(($user_finder_listbox.SelectedItem -split " ")[0]) "P3pp1n13ll0"}})
        
        $MenuItem1.MenuItems.Add($reset_password_MenuItem1) | Out-Null
        $MenuItem1.MenuItems.Add($reset_password_MenuItem2) | Out-Null
        $MenuItem1.MenuItems.Add($reset_password_MenuItem3) | Out-Null
        $MenuItem1.MenuItems.Add($reset_password_MenuItem4) | Out-Null
        $MenuItem1.MenuItems.Add($reset_password_MenuItem5) | Out-Null

        $MenuItem2 = New-Object System.Windows.Forms.MenuItem
        $MenuItem2.Name = 'user_finder_menu_item2'
        $MenuItem2.Text = 'Group direct add..'
        $MenuItem2.add_Click({ if ($user_finder_listbox.SelectedIndex -gt -1) {ADGroupDirectAdd $(($user_finder_listbox.SelectedItem -split " ")[0])}})
        $ContextMenu.MenuItems.Add($MenuItem2) | Out-Null

        $MenuItem3 = New-Object System.Windows.Forms.MenuItem
        $MenuItem3.Name = 'user_finder_menu_item3'
        $MenuItem3.Text = 'Membership..'
        $MenuItem3.add_Click({ if ($user_finder_listbox.SelectedIndex -gt -1) {AD-RemoveUserGroups $(($user_finder_listbox.SelectedItem -split " ")[0])}})
        $ContextMenu.MenuItems.Add($MenuItem3) | Out-Null
        
        $MenuItem4 = New-Object System.Windows.Forms.MenuItem
        $MenuItem4.Name = 'user_finder_menu_item3'
        $MenuItem4.Text = 'View and edit logon script..'
        $MenuItem4.add_Click({ if ($user_finder_listbox.SelectedIndex -gt -1) {EditLogonScript $(($user_finder_listbox.SelectedItem -split " ")[0])}})
        $ContextMenu.MenuItems.Add($MenuItem4) | Out-Null
        
        $MenuItem5 = New-Object System.Windows.Forms.MenuItem
        $MenuItem5.Name = 'user_finder_menu_item5'
        $MenuItem5.Text = 'Details..'
        $MenuItem5.add_Click({ if ($user_finder_listbox.SelectedIndex -gt -1) {ShowUserDetails $(($user_finder_listbox.SelectedItem -split " ")[0])}})
        $ContextMenu.MenuItems.Add($MenuItem5) | Out-Null
        
        Write-Verbose "Attaching the user finder listbox context menu.."
        $user_finder_listBox.ContextMenu = $ContextMenu
        Write-Verbose "Adding the user finder listbox to the main form.."
        $main_form.Controls.Add($user_finder_listBox) 

        Write-Verbose "Creating user finder COPY SELECTED button.."
        $user_copier_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $user_copier_button.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $user_copier_button.Location = New-Object System.Drawing.Size(500,55)
        $user_copier_button.Name = "user_copier_button"
        $user_copier_button.Size = New-Object System.Drawing.Size(135,23)
        $user_copier_button.TabIndex = 29
        $user_copier_button.Text = "COPY SELECTED"
        $user_copier_button.Enabled = $false
        $user_copier_button.Visible = $false
        $user_copier_button.UseVisualStyleBackColor = $True
        $user_copier_button.add_Click($user_copier_button_OnClick)
        $main_form.Controls.Add($user_copier_button)

        Write-Verbose "Creating user finder Querying label.."
        $user_finder_querying_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $user_finder_querying_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,0,0)
        $user_finder_querying_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $user_finder_querying_label.Font = New-Object System.Drawing.Font("Gisha",11.25,1,3,0)
        $user_finder_querying_label.Location = New-Object System.Drawing.Point(500,57)
        $user_finder_querying_label.Name = "user_finder_querying_label"
        $user_finder_querying_label.Size = New-Object System.Drawing.Size(200,30)
        $user_finder_querying_label.TabIndex = 86
        $user_finder_querying_label.Text = "Querying DCs.."
        $user_finder_querying_label.Visible = $false
        $main_form.Controls.Add($user_finder_querying_label)

        Write-Verbose "Creating user finder picturebox.."
        $user_finder_picturebox.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $user_finder_picturebox.Cursor = [System.Windows.Forms.Cursors]::No
        $user_finder_picturebox.DataBindings.DefaultDataSourceUpdateMode = 0
        $user_finder_picturebox.Location = New-Object System.Drawing.Size(650,55)
        $user_finder_picturebox.Name = "user_finder_picturebox"
        $user_finder_picturebox.Size = New-Object System.Drawing.Size(75,75)
        $user_finder_picturebox.SizeMode = 4  # "zoom" the picture
        $user_finder_picturebox.TabIndex =33
        $user_finder_picturebox.TabStop = $False
        $user_finder_picturebox.Add_MouseHover($user_finder_picturebox_OnHover)
        $main_form.Controls.Add($user_finder_picturebox)

        Write-Verbose "Creating user finder [account] PASSWORD EXPIRED label.."
        $passwordexpired_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $passwordexpired_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $passwordexpired_label.Font = New-Object System.Drawing.Font("Gisha",6,1,3,0)
        $passwordexpired_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,0,0)
        $passwordexpired_label.Location = New-Object System.Drawing.Point(655,135)
        $passwordexpired_label.Name = "passwordexpired_label"
        $passwordexpired_label.Size = New-Object System.Drawing.Size(62,29)
        $passwordexpired_label.TabIndex = 34
        $passwordexpired_label.Text = "PASSWORD EXPIRED"
        $passwordexpired_label.TextAlign = 32
        $passwordexpired_label.Visible = $false
        $main_form.Controls.Add($passwordexpired_label)

        Write-Verbose "Creating user finder [account] DISABLED label.."
        $accountdisabled_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $accountdisabled_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $accountdisabled_label.Font = New-Object System.Drawing.Font("Gisha",9.75,1,3,0)
        $accountdisabled_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,0,0)
        $accountdisabled_label.Location = New-Object System.Drawing.Point(655,163)
        $accountdisabled_label.Name = "accountdisabled_label"
        $accountdisabled_label.Size = New-Object System.Drawing.Size(77,15)
        $accountdisabled_label.TabIndex = 35
        $accountdisabled_label.Text = "DISABLED"
        $accountdisabled_label.Visible = $false
        $main_form.Controls.Add($accountdisabled_label)

        Write-Verbose "Creating user finder [account] LOCKED label.."
        $accountlocked_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $accountlocked_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $accountlocked_label.Font = New-Object System.Drawing.Font("Gisha",9.75,1,3,0)
        $accountlocked_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,0,0)
        $accountlocked_label.Location = New-Object System.Drawing.Point(660,183)
        $accountlocked_label.Name = "accountlocked_label"
        $accountlocked_label.Size = New-Object System.Drawing.Size(66,15)
        $accountlocked_label.TabIndex = 36
        $accountlocked_label.Text = "LOCKED"
        $accountlocked_label.Visible = $false
        $main_form.Controls.Add($accountlocked_label)

        Write-Verbose "Creating unlock account link.."
        $accountunlock_link.DataBindings.DefaultDataSourceUpdateMode = 0
        $accountunlock_link.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $accountunlock_link.LinkColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $accountunlock_link.Location = New-Object System.Drawing.Point(667,203)
        $accountunlock_link.Name = "accountunlock_link"
        $accountunlock_link.Size = New-Object System.Drawing.Size(50,16)
        $accountunlock_link.TabIndex = 37
        $accountunlock_link.TabStop = $True
        $accountunlock_link.Text = "unlock"
        $accountunlock_link.Visible = $false
        $accountunlock_link.add_Click($accountunlock_link_OnClick)
        $main_form.Controls.Add($accountunlock_link)
        #endregion USER FINDER

        #region MACHINE FINDER
        Write-Verbose "Creating machine finder label.."
        $machine_finder_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $machine_finder_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $machine_finder_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $machine_finder_label.Font = New-Object System.Drawing.Font("Gisha",15.75,1,3,0)
        $machine_finder_label.Location = New-Object System.Drawing.Size(747,18)
        $machine_finder_label.Name = "machine_finder_label"
        $machine_finder_label.Size = New-Object System.Drawing.Size(200,30)
        $machine_finder_label.TabIndex = 50
        $machine_finder_label.Text = "Machine finder:"
        $main_form.Controls.Add($machine_finder_label)

        Write-Verbose "Creating machine finder input box.."
        $machine_finder_textbox.DataBindings.DefaultDataSourceUpdateMode = 0
        $machine_finder_textbox.Font = $standard_font
        $machine_finder_textbox.Location = New-Object System.Drawing.Size(750,55)
        $machine_finder_textbox.Name = "machine_finder_textbox"
        $machine_finder_textbox.Size = New-Object System.Drawing.Size(115,20)
        $machine_finder_textbox.TabIndex = 51
        $machine_finder_textbox.Add_KeyDown({if ($_.KeyCode -eq "Enter") { $machine_finder_button.PerformClick() }})
        $main_form.Controls.Add($machine_finder_textbox)

        Write-Verbose "Creating machine finder GO button.."
        $machine_finder_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $machine_finder_button.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $machine_finder_button.Location = New-Object System.Drawing.Point(880,55)
        $machine_finder_button.Name = "machine_finder_button"
        $machine_finder_button.Size = New-Object System.Drawing.Size(35,23)
        $machine_finder_button.TabIndex = 52
        $machine_finder_button.Text = "GO"
        $machine_finder_button.UseVisualStyleBackColor = $True
        $machine_finder_button.add_Click($machine_finder_button_OnClick)
        $main_form.Controls.Add($machine_finder_button)

        Write-Verbose "Creating machine finder GO DEEP button.."
        $machine_finder_button2.DataBindings.DefaultDataSourceUpdateMode = 0
        $machine_finder_button2.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $machine_finder_button2.Location = New-Object System.Drawing.Point(927,55)
        $machine_finder_button2.Name = "machine_finder_button2"
        $machine_finder_button2.Size = New-Object System.Drawing.Size(65,23)
        $machine_finder_button2.TabIndex = 92
        $machine_finder_button2.Text = "GO DEEP"
        $machine_finder_button2.UseVisualStyleBackColor = $True
        $machine_finder_button2.add_Click($machine_finder_button2_OnClick)
        $main_form.Controls.Add($machine_finder_button2)

        Write-Verbose "Creating machine finder COPY SELECTED button.."
        $machine_copier_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $machine_copier_button.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $machine_copier_button.Location = New-Object System.Drawing.Point(1004,55)
        $machine_copier_button.Name = "machine_copier_button"
        $machine_copier_button.Size = New-Object System.Drawing.Size(105,23)
        $machine_copier_button.TabIndex = 53
        $machine_copier_button.Text = "COPY SELECTED"
        $machine_copier_button.Enabled = $false
        $machine_copier_button.Visible = $true
        $machine_copier_button.UseVisualStyleBackColor = $True
        $machine_copier_button.add_Click($machine_copier_button_OnClick)
        $main_form.Controls.Add($machine_copier_button)

        Write-Verbose "Creating machine finder Querying label.."
        $machine_finder_querying_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $machine_finder_querying_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,0,0)
        $machine_finder_querying_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $machine_finder_querying_label.Font = New-Object System.Drawing.Font("Gisha",11.25,1,3,0)
        $machine_finder_querying_label.Location = New-Object System.Drawing.Point(880,55)
        $machine_finder_querying_label.Name = "machine_finder_querying_label"
        $machine_finder_querying_label.Size = New-Object System.Drawing.Size(400,30)
        $machine_finder_querying_label.TabIndex = 82
        $machine_finder_querying_label.Text = "Querying vCenter.."
        $machine_finder_querying_label.Visible = $false
        $main_form.Controls.Add($machine_finder_querying_label)

        Write-Verbose "Creating machine finder results listbox.."
        $machine_finder_listBox.Location = New-Object System.Drawing.Size(750,90)
        $machine_finder_listBox.Size = New-Object System.Drawing.Size(250,137)
        $machine_finder_listBox.Font = $standard_font
        $machine_finder_listBox.SelectionMode = "One"
        $machine_finder_listBox.Visible = $false
        $machine_finder_listBox.Add_MouseDown($machine_finder_listBox_MouseDown)

        Write-Verbose "Creating a small context menu for the machine finder listbox.."
        $machine_finder_ContextMenu = New-Object System.Windows.Forms.ContextMenu

        $machine_finder_MenuItem0 = New-Object System.Windows.Forms.MenuItem
        $machine_finder_MenuItem0.Name = 'machine_finder_MenuItem0'
        $machine_finder_MenuItem0.Text = 'Open remote desktop connection..'
        $machine_finder_MenuItem0.add_Click({ if ($machine_finder_listBox.SelectedIndex -gt -1) { OpenRDConnection }})
        $machine_finder_ContextMenu.MenuItems.Add($machine_finder_MenuItem0) | Out-Null

        $machine_finder_MenuItem1 = New-Object System.Windows.Forms.MenuItem
        $machine_finder_MenuItem1.Name = 'machine_finder_MenuItem1'
        $machine_finder_MenuItem1.Text = 'Open Computer Management..'
        $machine_finder_MenuItem1.add_Click({ if ($machine_finder_listBox.SelectedIndex -gt -1) { OpenComputerManagement }})
        $machine_finder_ContextMenu.MenuItems.Add($machine_finder_MenuItem1) | Out-Null

        $machine_finder_MenuItem2 = New-Object System.Windows.Forms.MenuItem
        $machine_finder_MenuItem2.Name = 'machine_finder_MenuItem2'
        $machine_finder_MenuItem2.Text = 'shutdown -i..'
        $machine_finder_MenuItem2.add_Click({ if ($machine_finder_listBox.SelectedIndex -gt -1) { iShutdown }})
        $machine_finder_ContextMenu.MenuItems.Add($machine_finder_MenuItem2) | Out-Null

        $machine_finder_MenuItem3 = New-Object System.Windows.Forms.MenuItem
        $machine_finder_MenuItem3.Name = 'machine_finder_MenuItem3'
        $machine_finder_MenuItem3.Text = '\\<hostname>..'
        $machine_finder_MenuItem3.add_Click({ if ($machine_finder_listBox.SelectedIndex -gt -1) { ExploreMachine }})
        $machine_finder_ContextMenu.MenuItems.Add($machine_finder_MenuItem3) | Out-Null

        $machine_finder_MenuItem4 = New-Object System.Windows.Forms.MenuItem
        $machine_finder_MenuItem4.Name = 'machine_finder_MenuItem4'
        $machine_finder_MenuItem4.Text = 'Tasks && events (max 100, max last 7 days)..'
        $machine_finder_MenuItem4.add_Click({ if ($machine_finder_listBox.SelectedIndex -gt -1) { ViewTasksEvents }})
        $machine_finder_ContextMenu.MenuItems.Add($machine_finder_MenuItem4) | Out-Null

        $machine_finder_MenuItem5 = New-Object System.Windows.Forms.MenuItem
        $machine_finder_MenuItem5.Name = 'machine_finder_MenuItem5'
        $machine_finder_MenuItem5.Text = 'Reset VM (forced)'
        $machine_finder_MenuItem5.add_Click({ if ($machine_finder_listBox.SelectedIndex -gt -1) { ResetVM }})
        $machine_finder_ContextMenu.MenuItems.Add($machine_finder_MenuItem5) | Out-Null

        $machine_finder_MenuItem6 = New-Object System.Windows.Forms.MenuItem
        $machine_finder_MenuItem6.Name = 'machine_finder_MenuItem6'
        $machine_finder_MenuItem6.Text = 'More power options'
        $machine_finder_MenuItem6.add_Click({ if ($machine_finder_listBox.SelectedIndex -gt -1) { ResetVM }})
        $machine_finder_ContextMenu.MenuItems.Add($machine_finder_MenuItem6) | Out-Null

        $power_options_MenuItem1 = New-Object System.Windows.Forms.MenuItem
        $power_options_MenuItem1.Name = 'power_options_MenuItem1'
        $power_options_MenuItem1.Text = 'Power on'
        $power_options_MenuItem1.add_Click({ if ($machine_finder_listBox.SelectedIndex -gt -1) {AdministerVM $this.text}})

        $power_options_MenuItem2 = New-Object System.Windows.Forms.MenuItem
        $power_options_MenuItem2.Name = 'power_options_MenuItem2'
        $power_options_MenuItem2.Text = 'Power off'
        $power_options_MenuItem2.add_Click({ if ($machine_finder_listBox.SelectedIndex -gt -1) {AdministerVM $this.text}})

        $power_options_MenuItem3 = New-Object System.Windows.Forms.MenuItem
        $power_options_MenuItem3.Name = 'power_options_MenuItem3'
        $power_options_MenuItem3.Text = 'Suspend'
        $power_options_MenuItem3.add_Click({ if ($machine_finder_listBox.SelectedIndex -gt -1) {AdministerVM $this.text}})

        $power_options_MenuItem4 = New-Object System.Windows.Forms.MenuItem
        $power_options_MenuItem4.Name = 'power_options_MenuItem4'
        $power_options_MenuItem4.Text = 'Shutdown guest OS'
        $power_options_MenuItem4.add_Click({ if ($machine_finder_listBox.SelectedIndex -gt -1) {AdministerVM $this.text}})

        $power_options_MenuItem5 = New-Object System.Windows.Forms.MenuItem
        $power_options_MenuItem5.Name = 'power_options_MenuItem5'
        $power_options_MenuItem5.Text = 'Restart guest OS'
        $power_options_MenuItem5.add_Click({ if ($machine_finder_listBox.SelectedIndex -gt -1) {AdministerVM $this.text}})
        
        $machine_finder_MenuItem6.MenuItems.Add($power_options_MenuItem1) | Out-Null
        $machine_finder_MenuItem6.MenuItems.Add($power_options_MenuItem2) | Out-Null
        $machine_finder_MenuItem6.MenuItems.Add($power_options_MenuItem3) | Out-Null
        $machine_finder_MenuItem6.MenuItems.Add($power_options_MenuItem4) | Out-Null
        $machine_finder_MenuItem6.MenuItems.Add($power_options_MenuItem5) | Out-Null

        $machine_finder_MenuItem7 = New-Object System.Windows.Forms.MenuItem
        $machine_finder_MenuItem7.Name = 'machine_finder_MenuItem7'
        $machine_finder_MenuItem7.Text = 'VM details..'
        $machine_finder_MenuItem7.add_Click({ if ($machine_finder_listBox.SelectedIndex -gt -1) { MachineDetails }})
        $machine_finder_ContextMenu.MenuItems.Add($machine_finder_MenuItem7) | Out-Null
        
        Write-Verbose "Attaching the machine finder listbox context menu.."
        $machine_finder_listBox.ContextMenu = $machine_finder_ContextMenu
        Write-Verbose "Adding the machine finder listbox to the main form.."
        $main_form.Controls.Add($machine_finder_listBox)

        Write-Verbose "Creating machine finder picturebox.."
        $machine_finder_picturebox.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $machine_finder_picturebox.Cursor = [System.Windows.Forms.Cursors]::No
        $machine_finder_picturebox.DataBindings.DefaultDataSourceUpdateMode = 0
        $machine_finder_picturebox.Location = New-Object System.Drawing.Size(1020,80)
        $machine_finder_picturebox.Name = "machine_finder_picturebox"
        $machine_finder_picturebox.Size = New-Object System.Drawing.Size(75,75)
        $machine_finder_picturebox.SizeMode = 4  # "zoom" the picture
        $machine_finder_picturebox.TabStop = $False
        $machine_finder_picturebox.ImageLocation = $standard_win_img
        $machine_finder_picturebox.Visible = $false
        $machine_finder_picturebox.BorderStyle = 0
        $main_form.Controls.Add($machine_finder_picturebox)

        Write-Verbose "Creating machine finder REACHABLE label.."
        $machine_finder_reachable_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $machine_finder_reachable_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $machine_finder_reachable_label.Font = New-Object System.Drawing.Font("Gisha",7,1,3,0)
        $machine_finder_reachable_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,0,0)
        $machine_finder_reachable_label.Location = New-Object System.Drawing.Point(1018,151)
        $machine_finder_reachable_label.Name = "machine_finder_reachable_label"
        $machine_finder_reachable_label.Size = New-Object System.Drawing.Size(80,20)
        $machine_finder_reachable_label.TabIndex = 83
        $machine_finder_reachable_label.Text = "REACHABLE"
        $machine_finder_reachable_label.TextAlign = 32
        $machine_finder_reachable_label.BorderStyle = 0
        $machine_finder_reachable_label.Visible = $false
        $main_form.Controls.Add($machine_finder_reachable_label)

        Write-Verbose "Creating machine finder CLUSTERED label.."
        $machine_finder_clustered_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $machine_finder_clustered_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $machine_finder_clustered_label.Font = New-Object System.Drawing.Font("Gisha",8,1,3,0)
        $machine_finder_clustered_label.ForeColor = [System.Drawing.Color]::FromArgb(255,0,200,0)
        $machine_finder_clustered_label.Location = New-Object System.Drawing.Point(1018,167)
        $machine_finder_clustered_label.Name = "machine_finder_clustered_label"
        $machine_finder_clustered_label.Size = New-Object System.Drawing.Size(80,20)
        $machine_finder_clustered_label.TabIndex = 84
        $machine_finder_clustered_label.Text = "CLUSTERED"
        $machine_finder_clustered_label.TextAlign = 32
        $machine_finder_clustered_label.BorderStyle = 0
        $machine_finder_clustered_label.Visible = $false
        $main_form.Controls.Add($machine_finder_clustered_label)

        Write-Verbose "Creating machine finder vCenter status label.."
        $machine_finder_vcenter_status_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $machine_finder_vcenter_status_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $machine_finder_vcenter_status_label.Font = New-Object System.Drawing.Font("Gisha",8,1,3,0)
        $machine_finder_vcenter_status_label.ForeColor = [System.Drawing.Color]::FromArgb(255,0,200,0)
        $machine_finder_vcenter_status_label.Location = New-Object System.Drawing.Point(1008,186)
        $machine_finder_vcenter_status_label.Name = "machine_finder_vcenter_status_label"
        $machine_finder_vcenter_status_label.Size = New-Object System.Drawing.Size(100,16)
        $machine_finder_vcenter_status_label.TabIndex = 85
        $machine_finder_vcenter_status_label.Text = "vCenter status"
        $machine_finder_vcenter_status_label.TextAlign = 32
        $machine_finder_vcenter_status_label.BorderStyle = 0
        $machine_finder_vcenter_status_label.Visible = $false
        $machine_finder_vcenter_status_label.add_Click({ VMStatusDetails })
        $main_form.Controls.Add($machine_finder_vcenter_status_label)

        Write-Verbose "Creating machine finder snapshot label.."
        $machine_finder_snapshot_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $machine_finder_snapshot_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $machine_finder_snapshot_label.Font = New-Object System.Drawing.Font("Gisha",8,1,3,0)
        $machine_finder_snapshot_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,0)
        $machine_finder_snapshot_label.LinkColor = [System.Drawing.Color]::FromArgb(255,255,255,0)
        $machine_finder_snapshot_label.Location = New-Object System.Drawing.Point(1008,207)
        $machine_finder_snapshot_label.Name = "machine_finder_snapshot_label"
        $machine_finder_snapshot_label.Size = New-Object System.Drawing.Size(100,16)
        $machine_finder_snapshot_label.TabIndex = 93
        $machine_finder_snapshot_label.Text = "HAS SNAPSHOTS"
        $machine_finder_snapshot_label.TextAlign = 32
        $machine_finder_snapshot_label.BorderStyle = 0
        $machine_finder_snapshot_label.Visible = $false
        $machine_finder_snapshot_label.add_Click({ VMSnapshotDetails })
        $main_form.Controls.Add($machine_finder_snapshot_label)
        #endregion  MACHINE FINDER

        #region MAILBOX FINDER
        $mailbox_finder_x_base = 305 # 305 for user finder
        $mailbox_finder_y_base = 355 # 18  for user finder
        $mailbox_finder_label = New-Object System.Windows.Forms.Label
        $mailbox_finder_textbox = New-Object System.Windows.Forms.TextBox
        $mailbox_finder_button = New-Object System.Windows.Forms.Button
        $mailbox_copier_button = New-Object System.Windows.Forms.Button
        $mailbox_finder_listBox = New-Object System.Windows.Forms.ListBox 
        $mailbox_finder_querying_label = New-Object System.Windows.Forms.Label
        $SCRIPT:mailbox_finder_listbox_orig_selectedindex = -1

        Write-Verbose "Creating mailbox finder label.."
        $mailbox_finder_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $mailbox_finder_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $mailbox_finder_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $mailbox_finder_label.Font = New-Object System.Drawing.Font("Gisha",15.75,1,3,0)
        $mailbox_finder_label.Location = New-Object System.Drawing.Point($mailbox_finder_x_base,$mailbox_finder_y_base)
        $mailbox_finder_label.Name = "mailbox_finder_label"
        $mailbox_finder_label.Size = New-Object System.Drawing.Size(250,30)
        $mailbox_finder_label.TabIndex = 87
        $mailbox_finder_label.Text = "Mailbox/DL finder:"
        $main_form.Controls.Add($mailbox_finder_label)

        Write-Verbose "Creating mailbox finder input box.."
        $mailbox_finder_textbox.DataBindings.DefaultDataSourceUpdateMode = 0
        $mailbox_finder_textbox.Font = $standard_font
        $mailbox_finder_textbox.Location = New-Object System.Drawing.Point($mailbox_finder_x_base,($mailbox_finder_y_base + 37))
        $mailbox_finder_textbox.Name = "mailbox_finder_textbox"
        $mailbox_finder_textbox.Size = New-Object System.Drawing.Size(140,20)
        $mailbox_finder_textbox.TabIndex = 88
        $mailbox_finder_textbox.Add_KeyDown({if ($_.KeyCode -eq "Enter") { $mailbox_finder_button.PerformClick() }})
        $main_form.Controls.Add($mailbox_finder_textbox)
        
        Write-Verbose "Creating mailbox finder GO button.."
        $mailbox_finder_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $mailbox_finder_button.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $mailbox_finder_button.Location = New-Object System.Drawing.Point(($mailbox_finder_x_base + 155),($mailbox_finder_y_base + 37))
        $mailbox_finder_button.Name = "user_finder_button"
        $mailbox_finder_button.Size = New-Object System.Drawing.Size(49,23)
        $mailbox_finder_button.TabIndex = 89
        $mailbox_finder_button.Text = "GO"
        $mailbox_finder_button.UseVisualStyleBackColor = $True
        $mailbox_finder_button.add_Click($mailbox_finder_button_OnClick)
        $main_form.Controls.Add($mailbox_finder_button)
        
        Write-Verbose "Creating mailbox finder COPY SELECTED button.."
        $mailbox_copier_button.DataBindings.DefaultDataSourceUpdateMode = 0
        $mailbox_copier_button.Font = New-Object System.Drawing.Font("Gisha",9,1,3,0)
        $mailbox_copier_button.Location = New-Object System.Drawing.Point(($mailbox_finder_x_base + 215),($mailbox_finder_y_base + 37))
        $mailbox_copier_button.Name = "mailbox_copier_button"
        $mailbox_copier_button.Size = New-Object System.Drawing.Size(115,23)
        $mailbox_copier_button.TabIndex = 90
        $mailbox_copier_button.Text = "COPY SELECTED"
        $mailbox_copier_button.Enabled = $false
        $mailbox_copier_button.Visible = $false
        $mailbox_copier_button.UseVisualStyleBackColor = $True
        $mailbox_copier_button.add_Click($mailbox_copier_button_OnClick)
        $main_form.Controls.Add($mailbox_copier_button)
        
        Write-Verbose "Creating mailbox finder results listbox.."
        $mailbox_finder_listBox.Location = New-Object System.Drawing.Point($mailbox_finder_x_base,($mailbox_finder_y_base + 72)) 
        $mailbox_finder_listBox.Size = New-Object System.Drawing.Size(330, (137 + 4))
        $mailbox_finder_listBox.Font = $standard_font
        $mailbox_finder_listBox.TabIndex = 91
        $mailbox_finder_listBox.SelectionMode = "One"
        $mailbox_finder_listBox.Visible = $false
        $mailbox_finder_listBox.Add_MouseDown($mailbox_finder_listBox_MouseDown)

        Write-Verbose "Creating a small context menu for the mailbox finder listbox.."
        $mailbox_finder_ContextMenu = New-Object System.Windows.Forms.ContextMenu

        $MenuItem0 = New-Object System.Windows.Forms.MenuItem
        $MenuItem0.Name = 'user_finder_menu_item0'
        $MenuItem0.Text = 'View and edit addresses'
        $MenuItem0.add_Click({ if ($user_finder_listbox.SelectedIndex -gt -1) {ToggleAccount $(($user_finder_listbox.SelectedItem -split " ")[0])}})
        $mailbox_finder_ContextMenu.MenuItems.Add($MenuItem0) | Out-Null

        $MenuItem1 = New-Object System.Windows.Forms.MenuItem
        $MenuItem1.Name = 'user_finder_menu_item1'
        $MenuItem1.Text = 'View permissions'
        $MenuItem1.add_Click({ if ($user_finder_listbox.SelectedIndex -gt -1) {ResetUserPassword $(($user_finder_listbox.SelectedItem -split " ")[0])}})
        $mailbox_finder_ContextMenu.MenuItems.Add($MenuItem1) | Out-Null

        $MenuItem2 = New-Object System.Windows.Forms.MenuItem
        $MenuItem2.Name = 'user_finder_menu_item2'
        $MenuItem2.Text = 'Increase storage quotas (if mailbox)'
        $MenuItem2.add_Click({ if ($user_finder_listbox.SelectedIndex -gt -1) {AD-RemoveUserGroups $(($user_finder_listbox.SelectedItem -split " ")[0])}})
        $mailbox_finder_ContextMenu.MenuItems.Add($MenuItem2) | Out-Null
        
        $MenuItem3 = New-Object System.Windows.Forms.MenuItem
        $MenuItem3.Name = 'user_finder_menu_item3'
        $MenuItem3.Text = 'View and edit members (if DL)'
        $MenuItem3.add_Click({ if ($user_finder_listbox.SelectedIndex -gt -1) {EditLogonScript $(($user_finder_listbox.SelectedItem -split " ")[0])}})
        $mailbox_finder_ContextMenu.MenuItems.Add($MenuItem3) | Out-Null
        
        $MenuItem4 = New-Object System.Windows.Forms.MenuItem
        $MenuItem4.Name = 'user_finder_menu_item4'
        $MenuItem4.Text = 'Object details'
        $MenuItem4.add_Click({ if ($user_finder_listbox.SelectedIndex -gt -1) {ShowUserDetails $(($user_finder_listbox.SelectedItem -split " ")[0])}})
        $mailbox_finder_ContextMenu.MenuItems.Add($MenuItem4) | Out-Null
        
        Write-Verbose "Attaching the mailbox finder listbox context menu.."
        $mailbox_finder_listBox.ContextMenu = $mailbox_finder_ContextMenu
        Write-Verbose "Adding the mailbox finder listbox to the main form.."
        $main_form.Controls.Add($mailbox_finder_listBox) 

        Write-Verbose "Creating mailbox finder Querying label.."
        $mailbox_finder_querying_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $mailbox_finder_querying_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,0,0)
        $mailbox_finder_querying_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $mailbox_finder_querying_label.Font = New-Object System.Drawing.Font("Gisha",11.25,1,3,0)
        $mailbox_finder_querying_label.Location = New-Object System.Drawing.Point(($mailbox_finder_x_base + 215),($mailbox_finder_y_base + 37))
        $mailbox_finder_querying_label.Name = "mailbox_finder_querying_label"
        $mailbox_finder_querying_label.Size = New-Object System.Drawing.Size(200,30)
        $mailbox_finder_querying_label.TabIndex = 92
        $mailbox_finder_querying_label.Text = "Querying Exchange.."
        $mailbox_finder_querying_label.Visible = $false
        $main_form.Controls.Add($mailbox_finder_querying_label)
        
        $mailbox_finder_details_label = New-Object System.Windows.Forms.Label
        $mailbox_finder_details_label.DataBindings.DefaultDataSourceUpdateMode = 0
        $mailbox_finder_details_label.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $mailbox_finder_details_label.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $mailbox_finder_details_label.Location = New-Object System.Drawing.Point($mailbox_finder_x_base,($mailbox_finder_y_base + 219))
        $mailbox_finder_details_label.Name = "mailbox_finder_details_label"
        $mailbox_finder_details_label.Size = New-Object System.Drawing.Size(350,16)
        $mailbox_finder_details_label.TabStop = $false
        $mailbox_finder_details_label.Visible = $false
        $mailbox_finder_details_label.Text = "Used MB: 350 (500/550/1024)  Members: 999  Auto forward: no"
        $main_form.Controls.Add($mailbox_finder_details_label)
        #endregion MAILBOX FINDER

        Write-Verbose "Creating hide (minimize to tray) link.."
        $main_form_hide_link.DataBindings.DefaultDataSourceUpdateMode = 0
        $main_form_hide_link.Font = New-Object System.Drawing.Font("Gisha",8.25,0,3,0)
        $main_form_hide_link.BackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
        $main_form_hide_link.LinkColor = [System.Drawing.Color]::FromArgb(255,255,255,255)
        $main_form_hide_link.Location = New-Object System.Drawing.Point(($main_form.Size.Width - 85),5)
        $main_form_hide_link.Name = "main_form_hide_link"
        $main_form_hide_link.Size = New-Object System.Drawing.Size(70,20)
        $main_form_hide_link.TabIndex = 33
        $main_form_hide_link.TabStop = $True
        $main_form_hide_link.Text = "hide window"
        $main_form_hide_link.add_Click($main_form_hide_link_OnClick)
        $main_form.Controls.Add($main_form_hide_link)
        #endregion form controls
        
        #Save the initial state of the form
        Write-Verbose "Saving the initial state of the main form.."
        $InitialFormWindowState = $main_form.WindowState
        #Init the OnLoad event to correct the initial state of the form
        Write-Verbose "Attaching the OnLoad event to the main form.."
        $main_form.add_Load($main_form_OnLoad)
        #Attaching an OnClose event to destroy the tray icon
        Write-Verbose "Attaching the OnClose event to the main form.."
        $main_form.add_FormClosing($main_form_OnClose)
        #Show the Form
        Write-Verbose "Showing the main form.."
        $main_form.ShowDialog() | Out-Null
    }

    #Call the Function to generate the main form and import stuff
    Write-Verbose "Importing AD, Exchange and VMware modules.."
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    Add-PSSnapin Microsoft.Exchange.Management.PowerShell.Admin -ErrorAction SilentlyContinue
    Add-PSSnapin VMware.VimAutomation.Core -ErrorAction SilentlyContinue
    $SCRIPT:common_parameters = ""
    $curdomain = Get-ADDomain -Current LocalComputer
    $curdomain_name = ($curdomain | Select Name).Name
    $curdomain_completename = ($curdomain | Select DNSRoot).DNSRoot
    $Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size(500,1000)
    Write-Host "Generating main form of Bitman's Toolbox."
    GenerateForm
  }

Set-Alias Bitman-Toolbox UI-Toolbox-Bitman
Set-Alias Toolbox-Bitman UI-Toolbox-Bitman
Set-Alias Misc-BitmanModuleInfo Module-Info
Export-ModuleMember -Function * -Alias *
Write-Host "If you are reading this, the module Bitman.psm1 was successfully loaded."
([string](0..18|%{[char][int](32+("54501434738477657832717765737614677977").substring(($_*2),2))})).replace(' ','')