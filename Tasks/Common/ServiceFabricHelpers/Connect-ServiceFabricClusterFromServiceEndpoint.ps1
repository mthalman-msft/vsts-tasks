# Function that can be mocked by tests
function Create-Object
{
    Param (
        [String]
        $TypeName,

        [Object[]]
        $ArgumentList
    )

    return New-Object -TypeName $TypeName -ArgumentList $ArgumentList
}

function Get-AadSecurityToken
{
    Param (
        [Hashtable]
        $ClusterConnectionParameters,
        
        $ConnectedServiceEndpoint
    )
    
    # Configure connection parameters to get cluster metadata
    $connectionParametersWithGetMetadata = $ClusterConnectionParameters.Clone()
    $connectionParametersWithGetMetadata.Add("GetMetadata", $true)
    
    # Query cluster metadata
    $connectResult = Connect-ServiceFabricCluster @connectionParametersWithGetMetadata
    $authority = $connectResult.AzureActiveDirectoryMetadata.Authority
    Write-Host (Get-VstsLocString -Key AadAuthority -ArgumentList $authority)
    $clusterApplicationId = $connectResult.AzureActiveDirectoryMetadata.ClusterApplication
    Write-Host (Get-VstsLocString -Key ClusterAppId -ArgumentList $clusterApplicationId)
    $clientApplicationId = $connectResult.AzureActiveDirectoryMetadata.ClientApplication
    Write-Host (Get-VstsLocString -Key ClientAppId -ArgumentList $clientApplicationId)

    # Acquire AAD access token
    $serverOMDirectory = Get-VstsTaskVariable -Name 'Agent.ServerOMDirectory' -Require
	Add-Type -LiteralPath "$serverOMDirectory\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"	
	$authContext = Create-Object -TypeName Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext -ArgumentList @($authority)
    $authParams = $ConnectedServiceEndpoint.Auth.Parameters
	$userCredential = Create-Object -TypeName Microsoft.IdentityModel.Clients.ActiveDirectory.UserCredential -ArgumentList @($authParams.Username, $authParams.Password)
    
    try
    {
        # Acquiring a token using UserCredential implies a non-interactive flow. No credential prompts will occur.
        $accessToken = $authContext.AcquireToken($clusterApplicationId, $clientApplicationId, $userCredential).AccessToken
    }
    catch
    {
        throw (Get-VstsLocString -Key ErrorOnAcquireToken -ArgumentList $_)
    }

    return $accessToken
}

function Add-Certificate
{
    Param (
        [Hashtable]
        $ClusterConnectionParameters,

        $ConnectedServiceEndpoint
    )

    $storeName = [System.Security.Cryptography.X509Certificates.StoreName]::My;
    $storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
   
    # Generate a certificate from the service endpoint values
    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2

    try
    {
        $bytes = [System.Convert]::FromBase64String($ConnectedServiceEndpoint.Auth.Parameters.Certificate)

        if ($ConnectedServiceEndpoint.Auth.Parameters.CertificatePassword)
        {
            $certificate.Import($bytes, $ConnectedServiceEndpoint.Auth.Parameters.CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
        }
        else
        {
            $certificate.Import($bytes)
        }
    }
    catch
    {
        throw (Get-VstsLocString -Key ErrorOnCertificateImport -ArgumentList $_)
    }
    
    # Add the certificate to the cert store.
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, $storeLocation)
    $store.Open(([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite))
    try
    {
        $store.Add($certificate)    
    }
    finally
    {
        $store.Close()
        $store.Dispose()
    }

    Write-Host (Get-VstsLocString -Key ImportedCertificate -ArgumentList $certificate.Thumbprint)

    # Override the certificate-related cluster connection parameters to known and supported values
    $ClusterConnectionParameters["FindType"] = "FindByThumbprint"
    $ClusterConnectionParameters["FindValue"] = $certificate.Thumbprint
    $ClusterConnectionParameters["StoreName"] = $storeName.ToString()
    $ClusterConnectionParameters["StoreLocation"] = $storeLocation.ToString()

    return $certificate
}

function Connect-ServiceFabricClusterFromServiceEndpoint {
    [CmdletBinding()]
    param(
        [Hashtable]
        $ClusterConnectionParameters,
        
        $ClusterEndpoint
    )

    Trace-VstsEnteringInvocation $MyInvocation
    try {

        $connectionEndpointUrl = [System.Uri]$ClusterEndpoint.Url

        $ClusterConnectionParameters["ConnectionEndpoint"] = $connectionEndpointUrl.Authority # Authority includes just the hostname and port

        # Configure cluster connection pre-reqs
        if ($ClusterEndpoint.Auth.Scheme -ne "None")
        {
            # Add server cert thumbprint (common to both auth-types)
            if ($ClusterEndpoint.Auth.Parameters.ServerCertThumbprint)
            {
                $ClusterConnectionParameters["ServerCertThumbprint"] = $ClusterEndpoint.Auth.Parameters.ServerCertThumbprint
            }

            # Add auth-specific parameters
            if ($ClusterEndpoint.Auth.Scheme -eq "UserNamePassword")
            {
                # Setup the AzureActiveDirectory and ServerCertThumbprint parameters before getting the security token, because getting the security token
                # requires a connection request to the cluster in order to get metadata and so these two parameters are needed for that request.
                $ClusterConnectionParameters["AzureActiveDirectory"] = $true

                $securityToken = Get-AadSecurityToken -ClusterConnectionParameters $ClusterConnectionParameters -ConnectedServiceEndpoint $ClusterEndpoint
                $ClusterConnectionParameters["SecurityToken"] = $securityToken
                $ClusterConnectionParameters["WarningAction"] = "SilentlyContinue"
            }
            elseif ($connectedServiceEndpoint.Auth.Scheme -eq "Certificate")
            {
                Add-Certificate -ClusterConnectionParameters $ClusterConnectionParameters -ConnectedServiceEndpoint $ClusterEndpoint
                $ClusterConnectionParameters["X509Credential"] = $true
            }
        }

        try {
            [void](Connect-ServiceFabricCluster @ClusterConnectionParameters)
        }
        catch {
            if ($connectionEndpointUrl.Port -ne "19000") {
                Write-Warning (Get-VstsLocString -Key DefaultPortWarning $connectionEndpointUrl.Port)
            }

            throw $_
        }

        Write-Host (Get-VstsLocString -Key ConnectedToCluster)
    
        # Reset the scope of the ClusterConnection variable that gets set by the call to Connect-ServiceFabricCluster so that it is available outside the scope of this module
        Set-Variable -Name ClusterConnection -Value $Private:ClusterConnection -Scope Global
    } finally {
        Trace-VstsLeavingInvocation $MyInvocation
    }
}