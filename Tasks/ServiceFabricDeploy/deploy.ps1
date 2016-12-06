# For more information on the VSTS Task SDK:
# https://github.com/Microsoft/vsts-task-lib

[CmdletBinding()]
param()

Trace-VstsEnteringInvocation $MyInvocation
try {
    # Import the localized strings. 
    Import-VstsLocStrings "$PSScriptRoot\task.json"
    
    # Load utility functions
    . "$PSScriptRoot\utilities.ps1"
    
    # Collect input values

    $publishProfilePath = Get-SinglePathOfType (Get-VstsInput -Name publishProfilePath) Leaf
    if ($publishProfilePath)
    {
        $publishProfile = Read-PublishProfile $publishProfilePath
    }

    $applicationPackagePath = Get-SinglePathOfType (Get-VstsInput -Name applicationPackagePath -Require) Container -Require

    $serviceConnectionName = Get-VstsInput -Name serviceConnectionName -Require
    $connectedServiceEndpoint = Get-VstsEndpoint -Name $serviceConnectionName -Require

    $copyPackageTimeoutSec = Get-VstsInput -Name copyPackageTimeoutSec
    $registerPackageTimeoutSec = Get-VstsInput -Name registerPackageTimeoutSec

    $clusterConnectionParameters = @{}
    
    $regKey = "HKLM:\SOFTWARE\Microsoft\Service Fabric SDK"
    if (!(Test-Path $regKey))
    {
        throw (Get-VstsLocString -Key ServiceFabricSDKNotInstalled)
    }

    if ($connectedServiceEndpoint.Auth.Scheme -ne "None" -and !$ConnectedServiceEndpoint.Auth.Parameters.ServerCertThumbprint)
    {
        Write-Warning (Get-VstsLocString -Key ServiceEndpointUpgradeWarning)
        if ($publishProfile)
        {
            $clusterConnectionParameters["ServerCertThumbprint"] = $publishProfile.ClusterConnectionParameters["ServerCertThumbprint"]
        }
        else
        {
            throw (Get-VstsLocString -Key PublishProfileRequiredServerThumbprint)
        }
    }
    
    Import-Module $PSScriptRoot\ps_modules\ServiceFabricHelpers

    # Connect to cluster
    Connect-ServiceFabricClusterFromServiceEndpoint -ClusterConnectionParameters $ClusterConnectionParameters -ClusterEndpoint $ConnectedServiceEndpoint
    
    . "$PSScriptRoot\ServiceFabricSDK\ServiceFabricSDK.ps1"

    $applicationParameterFile = Get-SinglePathOfType (Get-VstsInput -Name applicationParameterPath) Leaf
    if ($applicationParameterFile)
    {
        Write-Host (Get-VstsLocString -Key OverrideApplicationParameterFile -ArgumentList $applicationParameterFile) 
    }
    elseif ($publishProfile)
    {
        $applicationParameterFile = $publishProfile.ApplicationParameterFile
        Assert-VstsPath -LiteralPath $applicationParameterFile -PathType Leaf
    }
    else
    {
        throw (Get-VstsLocString -Key PublishProfileRequiredAppParams)
    }

    if ((Get-VstsInput -Name overridePublishProfileSettings) -eq "true")
    {
        Write-Host (Get-VstsLocString -Key OverrideUpgradeSettings)
        $isUpgrade = (Get-VstsInput -Name isUpgrade) -eq "true"

        if ($isUpgrade)
        {
            $upgradeParameters = Get-VstsUpgradeParameters
        }
    }
    elseif ($publishProfile)
    {
        $isUpgrade = $publishProfile.UpgradeDeployment -and $publishProfile.UpgradeDeployment.Enabled
        $upgradeParameters = $publishProfile.UpgradeDeployment.Parameters
    }
    else
    {
        throw (Get-VstsLocString -Key PublishProfileRequiredUpgrade)
    }

    $applicationName = Get-ApplicationNameFromApplicationParameterFile $applicationParameterFile
    $app = Get-ServiceFabricApplication -ApplicationName $applicationName

    # Do an upgrade if configured to do so and the app actually exists
    if ($isUpgrade -and $app)
    {
        $publishParameters = @{
            'ApplicationPackagePath' = $applicationPackagePath
            'ApplicationParameterFilePath' = $applicationParameterFile
            'Action' = "RegisterAndUpgrade"
            'UpgradeParameters' = $upgradeParameters
            'UnregisterUnusedVersions' = $true
            'ErrorAction' = "Stop"
        }

        if ($copyPackageTimeoutSec)
        {
            $publishParameters['CopyPackageTimeoutSec'] = $copyPackageTimeoutSec
        }

        if ($registerPackageTimeoutSec)
        {
            $publishParameters['RegisterPackageTimeoutSec'] = $registerPackageTimeoutSec
        }

        Publish-UpgradedServiceFabricApplication @publishParameters
    }
    else
    {
        $publishParameters = @{
            'ApplicationPackagePath' = $applicationPackagePath
            'ApplicationParameterFilePath' = $applicationParameterFile
            'Action' = "RegisterAndCreate"
            'OverwriteBehavior' = "SameAppTypeAndVersion"
            'ErrorAction' = "Stop"
        }

        if ($copyPackageTimeoutSec)
        {
            $publishParameters['CopyPackageTimeoutSec'] = $copyPackageTimeoutSec
        }

        if ($registerPackageTimeoutSec)
        {
            $publishParameters['RegisterPackageTimeoutSec'] = $registerPackageTimeoutSec
        }

        Publish-NewServiceFabricApplication @publishParameters
    }
} finally {
    Trace-VstsLeavingInvocation $MyInvocation
}