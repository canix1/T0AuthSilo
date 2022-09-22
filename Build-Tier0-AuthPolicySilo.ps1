<#
.Synopsis
    BlockInboundTrust.ps1
     
    AUTHOR: Robin Granberg (robin.granberg@protonmail.com)
    
    THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
    FITNESS FOR A PARTICULAR PURPOSE.
    
.DESCRIPTION
    A script that creates an Authentication Poicy and Silo for Tier 0

.EXAMPLE
    .\Build-Tier0-AuthPolicySilo.ps1 -create

   Creates an Authentication Poicy and Silo for Tier 0


.OUTPUTS
    

.LINK
    https://github.com/canix1/Build-Tier0-AuthPolicySilo

.NOTES
    Version: 1.0
    5 September, 2022


#>
Param
(
    # Run protect operations in the current domain
    [Parameter(Mandatory=$false, 
                ParameterSetName='')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch] 
    $create,

    # Name of the Authentication Policy
    [Parameter(Mandatory=$false, 
                ParameterSetName='')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [string]     
    $AuhtPolicyName = "AuthPolicy-Tier 0",


    # Name of the Authentication Policy Silo
    [Parameter(Mandatory=$false, 
                ParameterSetName='')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [string] 
    $AuhtPolicySiloName = "AuthSilo-Tier0",

    # List of computers
    [Parameter(Mandatory=$false, 
                ParameterSetName='')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [array]
    $t0computers,

    # List of computers
    [Parameter(Mandatory=$false, 
                ParameterSetName='')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [array] 
    $t0users
)
clear-host
Write-host  "********************************************"
Write-host  "Author: robin.granberg@protonmail.com"
Write-host  "twitter: @ipcdollar1"
Write-host  "github: https://github.com/canix1/Build-Tier0-AuthPolicySilo"
Write-host  "********************************************`n"

$VerbosePreference = "continue"


#Get the current domain name
$DomainDN = (get-addomain).DistinguishedName
#Get the configuration naming context
$configDN = (Get-ADDomain).SubordinateReferences | Where-Object{($_.Remove(16,($_.Length-16))) -eq "CN=Configuration"}
if($create)
{
    #Verify if the Authentication Policy already exist
    if(!(Get-ADAuthenticationPolicy -filter "Name -eq '$AuhtPolicyName'"))
    {
        #Create Authentication Policy
        New-ADAuthenticationPolicy -Name:$AuhtPolicyName  -Description:"Block Tier 0 accounts from accessing host outside of Tier 0" -Enforce:$true -RollingNTLMSecret:"Disabled" -UserAllowedToAuthenticateFrom:$('O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == "' +$AuhtPolicySiloName + '"))') -UserTGTLifetimeMins:240
        
        #Protect the Authentication Policy
        Set-ADAuthenticationPolicy -Identity:$AuhtPolicyName -ProtectedFromAccidentalDeletion:$true 

        Write-Host "Authentication Policy $($AuhtPolicyName) created!`n" -ForegroundColor Green

    }
    else
    {
        Write-Host ("Authentication Policy "+[char]34+"$($AuhtPolicyName)"+[char]34+" already exist! `n") -ForegroundColor Yellow
    }

    if(!(Get-ADAuthenticationPolicySilo -filter "Name -eq '$AuhtPolicySiloName'"))
    {
        #Create Authentication Policy Silo
        New-ADAuthenticationPolicySilo -Name:$AuhtPolicySiloName 

        #Update Authentication Policy with description and policy and protect it from deletion
        Set-ADAuthenticationPolicySilo -Identity:"CN=$AuhtPolicySiloName,CN=AuthN Silos,CN=AuthN Policy Configuration,CN=Services,$configDN" -Replace:@{"description"="Defined the boundary for Tier 0 accounts";"msDS-ComputerAuthNPolicy"="CN=$AuhtPolicyName,CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,$configDN";"msDS-ServiceAuthNPolicy"="CN=$AuhtPolicyName,CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,$configDN";"msDS-UserAuthNPolicy"="CN=$AuhtPolicyName,CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,$configDN"} -ProtectedFromAccidentalDeletion:$true 

        #Update Authentication Policy with enforcement
        Set-ADAuthenticationPolicySilo -Identity:"CN=$AuhtPolicySiloName,CN=AuthN Silos,CN=AuthN Policy Configuration,CN=Services,$configDN" -Replace:@{"msDS-AuthNPolicySiloEnforced"=$true}

        Write-Host "Authentication Policy Silo $($AuhtPolicySiloName) created!`n" -ForegroundColor Green
    }
    else
    {
        Write-Host ("Authentication Policy Silo "+[char]34+"$($AuhtPolicySiloName)"+[char]34+" already exist! `n") -ForegroundColor Yellow
    }
 



    if($t0computers)
    {
        $arrt0computers = @($t0computers.split(","))
        Foreach($computer in $arrt0computers)
        {
            if(Get-ADComputer -Filter "Name -eq '$computer'")
            {
                #Get the samaccountname of the computer object
                $SamAccountName = (Get-ADComputer -Filter "Name -eq '$computer'").SamAccountName
                #Add the computer to Authentication Policy Silo
                Grant-ADAuthenticationPolicySiloAccess -Identity $AuhtPolicySiloName -Account $SamAccountName
                #Add the Authentication Policy Silo to the computer
                Set-ADComputer -Identity $SamAccountName -AuthenticationPolicySilo $AuhtPolicySiloName
                
                Write-Host ("Granted computer "+[char]34+"$($SamAccountName)"+[char]34+" access to "+[char]34+"$($AuhtPolicySiloName)"+[char]34+"  `n") -ForegroundColor Green
            }
            else
            {
                Write-Host ("Computer "+[char]34+"$($SamAccountName)"+[char]34+" does not exist! `n") -ForegroundColor Yellow
            }
        }
    }

    if($t0users)
    {
        $arrt0users = @($t0users.split(","))
        Foreach($user in $arrt0users)
        {
            if(Get-ADUser -Filter "Name -eq '$user'")
            {
                #Add the user to Authentication Policy Silo
                Grant-ADAuthenticationPolicySiloAccess -Identity $AuhtPolicySiloName -Account $user
                #Add the Authentication Policy Silo to the user
                Set-ADUser -Identity $user -AuthenticationPolicySilo $AuhtPolicySiloName

                Write-Host ("Granted user "+[char]34+"$($user)"+[char]34+" access to "+[char]34+"$($AuhtPolicySiloName)"+[char]34+"  `n") -ForegroundColor Green
            }
            else
            {
                Write-Host ("User "+[char]34+"$($User)"+[char]34+" does not exist! `n") -ForegroundColor Yellow
            }
        }
    }
}