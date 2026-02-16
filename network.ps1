#requires -Version 7.0
# Copyright (c) 2026 Tim Alderweireldt. All rights reserved.
<#!
xyOps Network Event Plugin (PowerShell 7)
A collection of network diagnostic and analysis tools for xyOps including:
- IP Address Tools (validate, convert, subnet calculator)
- JWT Decoder
- Ping Test
- DNS Lookup
- Traceroute
- Port Scanner
- HTTP Status Checker
- SSL Certificate Checker
- WHOIS Lookup

I/O contract:
- Read one JSON object from STDIN (job), write progress/messages as JSON lines of the
  form: { "xy": 1, ... } to STDOUT.
- On success, emit: { "xy": 1, "code": 0, "data": <result>, "description": "..." }
- On error, emit:   { "xy": 1, "code": <nonzero>, "description": "..." } and exit 1.

Test locally:
  pwsh -NoProfile -ExecutionPolicy Bypass -File .\network.ps1 < job.json
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-XY {
  param([hashtable]$Object)
  $payload = [ordered]@{ xy = 1 }
  foreach ($k in $Object.Keys) { $payload[$k] = $Object[$k] }
  [Console]::Out.WriteLine(($payload | ConvertTo-Json -Depth 20 -Compress))
  [Console]::Out.Flush()
}

function Write-XYProgress {
  param([double]$Value, [string]$Status)
  $o = @{ progress = [math]::Round($Value, 4) }
  if ($Status) { $o.status = $Status }
  Write-XY $o
}

function Write-XYSuccess {
  param($Data, [string]$Description)
  $o = @{ code = 0; data = $Data }
  if ($Description) { $o.description = $Description }
  Write-XY $o
}

function Write-XYError {
  param([int]$Code, [string]$Description)
  Write-XY @{ code = $Code; description = $Description }
}

function Read-JobFromStdin {
  $raw = [Console]::In.ReadToEnd()
  if ([string]::IsNullOrWhiteSpace($raw)) { throw 'No job JSON received on STDIN' }
  return $raw | ConvertFrom-Json -ErrorAction Stop
}

function Get-NestedValue {
  param($Object, [string]$Path)
  if (-not $Path -or ($Path.Trim() -eq '')) { return $Object }
  $cur = $Object
  foreach ($part in $Path.Split('.')) {
    if ($null -eq $cur) { return $null }
    if ($cur -is [System.Collections.IDictionary]) {
      if (-not $cur.Contains($part)) { return $null }
      $cur = $cur[$part]
    }
    else {
      $cur = $cur.PSObject.Properties[$part].Value
    }
  }
  return $cur
}

# Safe parameter getter - returns default if property doesn't exist
function Get-Param {
  param($Params, [string]$Name, $Default = $null)
  if ($Params.PSObject.Properties.Name -contains $Name) { return $Params.$Name }
  return $Default
}

# Parse multiple inputs from string (comma/newline separated) or array
function Get-MultipleInputs {
  param($Value, [int]$MaxItems = 20)
  $items = @()
  if ($null -eq $Value) { return $items }
  # Check if it's a collection (Object[], ArrayList, etc.) but not a string
  if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
    $items = @($Value | ForEach-Object { if ($_ -is [string]) { $_.Trim() } else { [string]$_ } } | Where-Object { $_ -ne '' })
  } else {
    # Input is a string - split by comma or newline
    $items = @([string]$Value -split '[,\n\r]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
  }
  return @($items | Select-Object -First $MaxItems)
}

# ------------------------- IP Address Tools -------------------------
function Invoke-IPAddressTools {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  $mode = ($Params.ipMode ?? 'validate')
  $source = ($Params.ipSource ?? 'field')
  $ipInput = ''
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = ($Params.ipDataPath ?? '')
    $val = Get-NestedValue $inputData $path
    if ($null -eq $val) { throw "Data path '$path' not found in input data" }
    $ipInput = [string]$val
  } else { $ipInput = ($Params.ipInput ?? '') }
  
  if (-not $ipInput) { throw 'No IP address provided' }
  
  Write-XYProgress 0.5 'Processing IP address...'
  
  $ipInput = $ipInput.Trim()
  $rows = @()
  $result = @{ tool='IP Address Tools'; mode=$mode; input=$ipInput }
  
  switch ($mode) {
    'validate' {
      $ipv4Valid = $false; $ipv6Valid = $false; $type = 'Invalid'
      try {
        $ip = [System.Net.IPAddress]::Parse($ipInput)
        if ($ip.AddressFamily -eq 'InterNetwork') { $ipv4Valid = $true; $type = 'IPv4' }
        elseif ($ip.AddressFamily -eq 'InterNetworkV6') { $ipv6Valid = $true; $type = 'IPv6' }
      } catch {}
      $isPrivate = $false; $isLoopback = $false; $class = 'N/A'
      if ($ipv4Valid) {
        $octets = $ipInput -split '\.' | ForEach-Object { [int]$_ }
        if ($octets[0] -eq 10) { $isPrivate = $true }
        elseif ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) { $isPrivate = $true }
        elseif ($octets[0] -eq 192 -and $octets[1] -eq 168) { $isPrivate = $true }
        elseif ($octets[0] -eq 127) { $isLoopback = $true }
        if ($octets[0] -le 127) { $class = 'A' }
        elseif ($octets[0] -le 191) { $class = 'B' }
        elseif ($octets[0] -le 223) { $class = 'C' }
        elseif ($octets[0] -le 239) { $class = 'D (Multicast)' }
        else { $class = 'E (Reserved)' }
      }
      $rows = @(@('IP Address', $ipInput), @('Valid', $(if ($ipv4Valid -or $ipv6Valid) { '✓ Yes' } else { '✗ No' })), @('Type', $type), @('Class', $class), @('Private', $(if ($isPrivate) { 'Yes' } else { 'No' })), @('Loopback', $(if ($isLoopback) { 'Yes' } else { 'No' })))
      $result.valid = ($ipv4Valid -or $ipv6Valid); $result.type = $type; $result.class = $class; $result.isPrivate = $isPrivate; $result.isLoopback = $isLoopback
    }
    'toDecimal' {
      $octets = $ipInput -split '\.' | ForEach-Object { [int]$_ }
      if ($octets.Count -ne 4) { throw 'Invalid IPv4 address' }
      $decimal = ([long]$octets[0] * 16777216) + ([long]$octets[1] * 65536) + ([long]$octets[2] * 256) + [long]$octets[3]
      $rows = @(@('IPv4 Address', $ipInput), @('Decimal', $decimal))
      $result.decimal = $decimal
    }
    'fromDecimal' {
      $dec = [long]$ipInput
      $o1 = [Math]::Floor($dec / 16777216) % 256; $o2 = [Math]::Floor($dec / 65536) % 256
      $o3 = [Math]::Floor($dec / 256) % 256; $o4 = $dec % 256
      $ipv4 = "$o1.$o2.$o3.$o4"
      $rows = @(@('Decimal', $dec), @('IPv4 Address', $ipv4))
      $result.ipv4 = $ipv4
    }
    'toBinary' {
      $octets = $ipInput -split '\.' | ForEach-Object { [int]$_ }
      if ($octets.Count -ne 4) { throw 'Invalid IPv4 address' }
      $binary = ($octets | ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, '0') }) -join '.'
      $rows = @(@('IPv4 Address', $ipInput), @('Binary', $binary))
      $result.binary = $binary
    }
    'subnet' {
      if ($ipInput -notmatch '/') { throw 'Please provide IP in CIDR notation (e.g., 192.168.1.0/24)' }
      $parts = $ipInput -split '/'; $ip = $parts[0]; $cidr = [int]$parts[1]
      $octets = $ip -split '\.' | ForEach-Object { [int]$_ }
      $mask = ([Math]::Pow(2, 32) - [Math]::Pow(2, 32 - $cidr))
      $m1 = [Math]::Floor($mask / 16777216) % 256; $m2 = [Math]::Floor($mask / 65536) % 256
      $m3 = [Math]::Floor($mask / 256) % 256; $m4 = $mask % 256
      $subnetMask = "$m1.$m2.$m3.$m4"
      $networkAddr = "$($octets[0] -band $m1).$($octets[1] -band $m2).$($octets[2] -band $m3).$($octets[3] -band $m4)"
      $hostCount = [Math]::Pow(2, 32 - $cidr) - 2
      $rows = @(@('CIDR', $ipInput), @('Subnet Mask', $subnetMask), @('Network Address', $networkAddr), @('Usable Hosts', $(if ($hostCount -gt 0) { $hostCount } else { 0 })))
      $result.subnetMask = $subnetMask; $result.networkAddress = $networkAddr; $result.usableHosts = $hostCount
    }
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  $modeNames = @{ validate='Validate'; toDecimal='IP to Decimal'; fromDecimal='Decimal to IP'; toBinary='IP to Binary'; subnet='Subnet Calculator' }
  Write-XY @{ table = @{ title="IP Address - $($modeNames[$mode])"; header=@('Property','Value'); rows=$rows; caption='IP address processed' } }
  [pscustomobject]$result
}

# ------------------------- JWT Decoder -------------------------
function Invoke-JWTDecoder {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  $source = ($Params.jwtSource ?? 'field')
  $token = ''
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = ($Params.jwtDataPath ?? '')
    $val = Get-NestedValue $inputData $path
    if ($null -eq $val) { throw "Data path '$path' not found in input data" }
    $token = [string]$val
  } else { $token = ($Params.jwtInput ?? '') }
  
  if (-not $token) { throw 'No JWT token provided' }
  
  Write-XYProgress 0.5 'Decoding JWT...'
  
  $token = $token.Trim()
  $parts = $token -split '\.'
  if ($parts.Count -ne 3) { throw 'Invalid JWT format (expected 3 parts separated by dots)' }
  
  # Base64URL decode helper
  $decodeBase64Url = {
    param($s)
    $s = $s.Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s))
  }
  
  $headerJson = & $decodeBase64Url $parts[0]
  $payloadJson = & $decodeBase64Url $parts[1]
  $header = $headerJson | ConvertFrom-Json
  $payload = $payloadJson | ConvertFrom-Json
  
  # Helper to safely get property from PSCustomObject
  $getProp = { param($obj, $name, $default)
    if ($null -ne $obj.PSObject -and $obj.PSObject.Properties.Name -contains $name) {
      $val = $obj.$name
      if ($null -ne $val) { return $val }
    }
    return $default
  }
  
  # Extract common claims
  $alg = & $getProp $header 'alg' 'N/A'
  $typ = & $getProp $header 'typ' 'N/A'
  $iss = & $getProp $payload 'iss' 'N/A'
  $sub = & $getProp $payload 'sub' 'N/A'
  $audVal = & $getProp $payload 'aud' $null
  $aud = if ($null -ne $audVal) { if ($audVal -is [array]) { $audVal -join ', ' } else { $audVal } } else { 'N/A' }
  $exp = 'N/A'; $expDate = 'N/A'
  $expVal = & $getProp $payload 'exp' $null
  if ($null -ne $expVal) {
    $exp = $expVal
    $expDate = [DateTimeOffset]::FromUnixTimeSeconds($expVal).DateTime.ToString('yyyy-MM-dd HH:mm:ss UTC')
  }
  $iat = 'N/A'; $iatDate = 'N/A'
  $iatVal = & $getProp $payload 'iat' $null
  if ($null -ne $iatVal) {
    $iat = $iatVal
    $iatDate = [DateTimeOffset]::FromUnixTimeSeconds($iatVal).DateTime.ToString('yyyy-MM-dd HH:mm:ss UTC')
  }
  
  $isExpired = $false
  if ($null -ne $expVal) { $isExpired = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -gt $expVal }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  Write-XY @{ table = @{ title='JWT Header'; header=@('Property','Value'); rows=@(@('Algorithm', $alg), @('Type', $typ)); caption='' } }
  Write-XY @{ table = @{ title='JWT Payload'; header=@('Property','Value'); rows=@(@('Issuer (iss)', $iss), @('Subject (sub)', $sub), @('Audience (aud)', $aud), @('Issued At (iat)', "$iat ($iatDate)"), @('Expires (exp)', "$exp ($expDate)"), @('Expired?', $(if ($isExpired) { '✗ Yes' } else { '✓ No' }))); caption=$(if ($isExpired) { 'Token has expired' } else { 'Token is still valid' }) } }
  Write-XY @{ text = @{ title='Full Payload'; content=$payloadJson; caption='' } }
  [pscustomobject]@{ tool='JWT Decoder'; algorithm=$alg; type=$typ; issuer=$iss; subject=$sub; audience=$aud; issuedAt=$iat; expiresAt=$exp; isExpired=$isExpired; header=$header; payload=$payload }
}

# ------------------------- Ping Test -------------------------
function Invoke-PingTest {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'pingSource' 'field'
  $hostsInput = $null
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'pingDataPath' ''
    $hostsInput = Get-NestedValue $inputData $path
    if ($null -eq $hostsInput) { throw "Data path '$path' not found in input data" }
  } else { $hostsInput = Get-Param $Params 'pingHosts' '' }
  
  $hosts = @(Get-MultipleInputs $hostsInput 20)
  if ($hosts.Count -eq 0) { throw 'No host(s) specified' }
  
  $count = [Math]::Min(10, [Math]::Max(1, [int](Get-Param $Params 'pingCount' 4)))
  $timeout = [Math]::Min(30000, [Math]::Max(100, [int](Get-Param $Params 'pingTimeout' 1000)))
  
  Write-XYProgress 0.2 "Pinging $($hosts.Count) host(s)..."
  
  $pinger = [System.Net.NetworkInformation.Ping]::new()
  $allResults = [System.Collections.Generic.List[object]]::new()
  $totalSuccess = 0
  $totalFail = 0
  
  $hostIndex = 0
  foreach ($host_ in $hosts) {
    $hostIndex++
    Write-XYProgress (0.2 + (0.7 * $hostIndex / $hosts.Count)) "Pinging $host_..."
    
    $results = [System.Collections.Generic.List[object]]::new()
    $successful = 0
    $failed = 0
    $latencies = [System.Collections.Generic.List[long]]::new()
    $resolvedIP = ''
    $hostError = $null
    
    try {
      try { $resolvedIP = ([System.Net.Dns]::GetHostAddresses($host_) | Select-Object -First 1).ToString() } catch { }
      
      for ($i = 1; $i -le $count; $i++) {
        try {
          $reply = $pinger.Send($host_, $timeout)
          if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
            $successful++
            $latencies.Add($reply.RoundtripTime)
            $ttlVal = if ($null -ne $reply.Options) { $reply.Options.Ttl } else { '-' }
            $addrVal = if ($null -ne $reply.Address) { $reply.Address.ToString() } else { '-' }
            $results.Add([pscustomobject]@{ seq=$i; status='Success'; time="$($reply.RoundtripTime)ms"; ttl=$ttlVal; address=$addrVal })
          } else {
            $failed++
            $results.Add([pscustomobject]@{ seq=$i; status=$reply.Status.ToString(); time='-'; ttl='-'; address='-' })
          }
        } catch {
          $failed++
          $errMsg = $_.Exception.Message
          if ($errMsg.Length -gt 50) { $errMsg = $errMsg.Substring(0, 47) + '...' }
          $results.Add([pscustomobject]@{ seq=$i; status="Error: $errMsg"; time='-'; ttl='-'; address='-' })
        }
        if ($i -lt $count) { Start-Sleep -Milliseconds 100 }
      }
    } catch {
      $hostError = $_.Exception.Message
    }
    
    $minLatency = if ($latencies.Count -gt 0) { ($latencies | Measure-Object -Minimum).Minimum } else { $null }
    $maxLatency = if ($latencies.Count -gt 0) { ($latencies | Measure-Object -Maximum).Maximum } else { $null }
    $avgLatency = if ($latencies.Count -gt 0) { [Math]::Round(($latencies | Measure-Object -Average).Average, 2) } else { $null }
    $lossPercent = if ($count -gt 0) { [Math]::Round(($failed / $count) * 100, 1) } else { 100 }
    
    if ($successful -gt 0) { $totalSuccess++ } else { $totalFail++ }
    
    # Build output table for this host
    $rows = @()
    foreach ($r in $results) {
      $rows += ,@($r.seq, $r.status, $r.time, $r.ttl, $r.address)
    }
    $resultCaption = if ($hostError) { "Error: $hostError" } elseif ($successful -eq $count) { "All $count pings successful" } elseif ($successful -eq 0) { "All $count pings failed" } else { "$successful/$count successful, $lossPercent% loss" }
    Write-XY @{ table = @{ title="Ping Results - $host_"; header=@('Seq','Status','Time','TTL','Address'); rows=$rows; caption=$resultCaption } }
    
    $statsRows = @(
      @('Host', $host_),
      @('Resolved IP', $(if ($resolvedIP) { $resolvedIP } else { 'N/A' })),
      @('Packets Sent', $count),
      @('Packets Received', $successful),
      @('Loss Percentage', "$lossPercent%")
    )
    if ($latencies.Count -gt 0) {
      $statsRows += @(@('Min Latency', "${minLatency}ms"), @('Max Latency', "${maxLatency}ms"), @('Avg Latency', "${avgLatency}ms"))
    }
    Write-XY @{ table = @{ title="Statistics - $host_"; header=@('Metric','Value'); rows=$statsRows; caption='' } }
    
    $allResults.Add([pscustomobject]@{
      host=$host_; resolvedIP=$resolvedIP; count=$count; successful=$successful; failed=$failed
      lossPercent=$lossPercent; minLatency=$minLatency; maxLatency=$maxLatency; avgLatency=$avgLatency
      error=$hostError; results=$results.ToArray()
    })
  }
  $pinger.Dispose()
  
  # Summary table if multiple hosts
  if ($hosts.Count -gt 1) {
    $summaryRows = @()
    foreach ($r in $allResults) {
      $status = if ($r.successful -gt 0) { 'OK' } else { 'FAIL' }
      $avg = if ($null -ne $r.avgLatency) { "$($r.avgLatency)ms" } else { '-' }
      $summaryRows += ,@($r.host, $status, "$($r.lossPercent)%", $avg)
    }
    Write-XY @{ table = @{ title='Ping Summary'; header=@('Host','Status','Loss','Avg Latency'); rows=$summaryRows; caption="$totalSuccess/$($hosts.Count) hosts reachable" } }
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  if ($totalSuccess -eq 0) {
    throw "Ping failed: All $($hosts.Count) host(s) unreachable"
  }
  
  [pscustomobject]@{ tool='Ping Test'; hostsChecked=$hosts.Count; successful=$totalSuccess; failed=$totalFail; results=$allResults.ToArray() }
}

# ------------------------- DNS Lookup -------------------------
function Invoke-DnsLookup {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'dnsSource' 'field'
  $queriesInput = $null
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'dnsDataPath' ''
    $queriesInput = Get-NestedValue $inputData $path
    if ($null -eq $queriesInput) { throw "Data path '$path' not found in input data" }
  } else { $queriesInput = Get-Param $Params 'dnsQueries' '' }
  
  $queries = @(Get-MultipleInputs $queriesInput 20)
  if ($queries.Count -eq 0) { throw 'No query specified' }
  
  $recordType = Get-Param $Params 'dnsRecordType' 'A'
  $dnsServer = Get-Param $Params 'dnsServer' ''
  
  Write-XYProgress 0.2 "Resolving $recordType records for $($queries.Count) domain(s)..."
  
  $allResults = [System.Collections.Generic.List[object]]::new()
  $totalSuccess = 0
  $totalFail = 0
  
  $queryIndex = 0
  foreach ($query in $queries) {
    $queryIndex++
    Write-XYProgress (0.2 + (0.7 * $queryIndex / $queries.Count)) "Resolving $query..."
    
    $results = [System.Collections.Generic.List[object]]::new()
    $success = $true
    $errorMsg = ''
    
    try {
      if ($recordType -eq 'PTR') {
        $ip = [System.Net.IPAddress]::Parse($query)
        $hostEntry = [System.Net.Dns]::GetHostEntry($ip)
        $results.Add([pscustomobject]@{ type='PTR'; name=$query; value=$hostEntry.HostName; ttl='-' })
      }
      elseif ($recordType -eq 'A' -or $recordType -eq 'AAAA') {
        $addresses = [System.Net.Dns]::GetHostAddresses($query)
        foreach ($addr in $addresses) {
          if ($recordType -eq 'A' -and $addr.AddressFamily -eq 'InterNetwork') {
            $results.Add([pscustomobject]@{ type='A'; name=$query; value=$addr.ToString(); ttl='-' })
          }
          elseif ($recordType -eq 'AAAA' -and $addr.AddressFamily -eq 'InterNetworkV6') {
            $results.Add([pscustomobject]@{ type='AAAA'; name=$query; value=$addr.ToString(); ttl='-' })
          }
        }
        if ($results.Count -eq 0) { $results.Add([pscustomobject]@{ type=$recordType; name=$query; value='No records found'; ttl='-' }) }
      }
      else {
        $nslookupArgs = if ($dnsServer) { "-type=$recordType $query $dnsServer" } else { "-type=$recordType $query" }
        $output = & nslookup $nslookupArgs.Split(' ') 2>&1
        $outputText = $output -join "`n"
        
        switch ($recordType) {
          'MX' {
            $regMatches = [regex]::Matches($outputText, 'mail exchanger = (.+)')
            foreach ($m in $regMatches) {
              $parts = $m.Groups[1].Value.Trim() -split '\s+'
              $priority = if ($parts.Count -gt 1) { $parts[0] } else { '-' }
              $srv = if ($parts.Count -gt 1) { $parts[-1] } else { $parts[0] }
              $results.Add([pscustomobject]@{ type='MX'; name=$query; value="$priority $srv"; ttl='-' })
            }
          }
          'TXT' {
            $regMatches = [regex]::Matches($outputText, 'text\s*=\s*"([^"]+)"')
            foreach ($m in $regMatches) {
              $results.Add([pscustomobject]@{ type='TXT'; name=$query; value=$m.Groups[1].Value; ttl='-' })
            }
          }
          'NS' {
            $regMatches = [regex]::Matches($outputText, 'nameserver = (.+)')
            foreach ($m in $regMatches) {
              $results.Add([pscustomobject]@{ type='NS'; name=$query; value=$m.Groups[1].Value.Trim(); ttl='-' })
            }
          }
          'CNAME' {
            $regMatches = [regex]::Matches($outputText, 'canonical name = (.+)')
            foreach ($m in $regMatches) {
              $results.Add([pscustomobject]@{ type='CNAME'; name=$query; value=$m.Groups[1].Value.Trim(); ttl='-' })
            }
          }
          'SOA' {
            if ($outputText -match 'primary name server = ([^\s]+)') {
              $soa = $Matches[1]
              $results.Add([pscustomobject]@{ type='SOA'; name=$query; value="Primary: $soa"; ttl='-' })
            }
          }
        }
        if ($results.Count -eq 0) { $results.Add([pscustomobject]@{ type=$recordType; name=$query; value='No records found'; ttl='-' }) }
      }
      $totalSuccess++
    } catch {
      $success = $false
      $errorMsg = $_.Exception.Message
      $results.Add([pscustomobject]@{ type=$recordType; name=$query; value="Error: $errorMsg"; ttl='-' })
      $totalFail++
    }
    
    # Output table for this query
    $rows = @()
    foreach ($r in $results) {
      $rows += ,@($r.type, $r.name, $r.value, $r.ttl)
    }
    Write-XY @{ table = @{ title="DNS Lookup - $query ($recordType)"; header=@('Type','Name','Value','TTL'); rows=$rows; caption=$(if ($dnsServer) { "Using DNS server: $dnsServer" } else { 'Using system DNS' }) } }
    
    $allResults.Add([pscustomobject]@{ query=$query; recordType=$recordType; success=$success; results=$results.ToArray(); error=$errorMsg })
  }
  
  # Summary table if multiple queries
  if ($queries.Count -gt 1) {
    $summaryRows = @()
    foreach ($r in $allResults) {
      $status = if ($r.success) { 'OK' } else { 'FAIL' }
      $recordCount = ($r.results | Where-Object { $_.value -notmatch '^(Error|No records)' }).Count
      $summaryRows += ,@($r.query, $status, $recordCount)
    }
    Write-XY @{ table = @{ title='DNS Summary'; header=@('Query','Status','Records'); rows=$summaryRows; caption="$totalSuccess/$($queries.Count) queries successful" } }
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  [pscustomobject]@{ tool='DNS Lookup'; queriesChecked=$queries.Count; successful=$totalSuccess; failed=$totalFail; recordType=$recordType; dnsServer=$(if ($dnsServer) { $dnsServer } else { 'system' }); results=$allResults.ToArray() }
}

# ------------------------- Traceroute -------------------------
function Invoke-Traceroute {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'traceSource' 'field'
  $hostsInput = $null
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'traceDataPath' ''
    $hostsInput = Get-NestedValue $inputData $path
    if ($null -eq $hostsInput) { throw "Data path '$path' not found in input data" }
  } else { $hostsInput = Get-Param $Params 'traceHosts' '' }
  
  $hosts = @(Get-MultipleInputs $hostsInput 10)
  if ($hosts.Count -eq 0) { throw 'No host(s) specified' }
  
  $maxHops = [Math]::Min(64, [Math]::Max(1, [int](Get-Param $Params 'traceMaxHops' 30)))
  $timeout = [Math]::Min(10000, [Math]::Max(100, [int](Get-Param $Params 'traceTimeout' 3000)))
  $resolveNames = if ($Params.PSObject.Properties.Name -contains 'traceResolveNames') { [bool]$Params.traceResolveNames } else { $true }
  
  Write-XYProgress 0.2 "Tracing route to $($hosts.Count) host(s)..."
  
  $pinger = [System.Net.NetworkInformation.Ping]::new()
  $allResults = [System.Collections.Generic.List[object]]::new()
  $totalReached = 0
  
  $hostIndex = 0
  foreach ($host_ in $hosts) {
    $hostIndex++
    Write-XYProgress (0.2 + (0.7 * $hostIndex / $hosts.Count)) "Tracing $host_..."
    
    $options = [System.Net.NetworkInformation.PingOptions]::new()
    $buffer = [byte[]]::new(32)
    $results = [System.Collections.Generic.List[object]]::new()
    $reached = $false
    $destIP = ''
    
    try { $destIP = ([System.Net.Dns]::GetHostAddresses($host_) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).ToString() } catch { $destIP = $host_ }
    
    for ($ttl = 1; $ttl -le $maxHops; $ttl++) {
      $options.Ttl = $ttl
      $hopIP = '*'; $hopName = '*'; $hopTime = '*'
      
      try {
        $reply = $pinger.Send($host_, $timeout, $buffer, $options)
        if ($reply.Status -eq 'TtlExpired' -or $reply.Status -eq 'Success') {
          $hopIP = $reply.Address.ToString()
          $hopTime = "$($reply.RoundtripTime)ms"
          if ($resolveNames) {
            try { $hopName = ([System.Net.Dns]::GetHostEntry($reply.Address)).HostName } catch { $hopName = $hopIP }
          } else { $hopName = $hopIP }
          if ($reply.Status -eq 'Success') { $reached = $true }
        } elseif ($reply.Status -eq 'TimedOut') {
          $hopName = 'Request timed out'
        }
      } catch { $hopName = 'Error' }
      
      $results.Add([pscustomobject]@{ hop=$ttl; ip=$hopIP; hostname=$hopName; time=$hopTime })
      if ($reached) { break }
    }
    
    if ($reached) { $totalReached++ }
    
    $rows = @()
    foreach ($r in $results) { $rows += ,@($r.hop, $r.ip, $r.hostname, $r.time) }
    Write-XY @{ table = @{ title="Traceroute - $host_"; header=@('Hop','IP Address','Hostname','Time'); rows=$rows; caption=$(if ($reached) { "Destination reached in $($results.Count) hops" } else { "Destination not reached within $maxHops hops" }) } }
    
    $allResults.Add([pscustomobject]@{ host=$host_; destinationIP=$destIP; hopsUsed=$results.Count; reached=$reached; results=$results.ToArray() })
  }
  $pinger.Dispose()
  
  if ($hosts.Count -gt 1) {
    $summaryRows = @()
    foreach ($r in $allResults) {
      $status = if ($r.reached) { 'OK' } else { 'FAIL' }
      $summaryRows += ,@($r.host, $status, $r.hopsUsed)
    }
    Write-XY @{ table = @{ title='Traceroute Summary'; header=@('Host','Status','Hops'); rows=$summaryRows; caption="$totalReached/$($hosts.Count) hosts reached" } }
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  [pscustomobject]@{ tool='Traceroute'; hostsChecked=$hosts.Count; reached=$totalReached; maxHops=$maxHops; results=$allResults.ToArray() }
}

# ------------------------- Port Scanner -------------------------
function Invoke-PortScanner {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'portSource' 'field'
  $hostsInput = $null
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'portDataPath' ''
    $hostsInput = Get-NestedValue $inputData $path
    if ($null -eq $hostsInput) { throw "Data path '$path' not found in input data" }
  } else { $hostsInput = Get-Param $Params 'portHosts' '' }
  
  $hosts = @(Get-MultipleInputs $hostsInput 20)
  if ($hosts.Count -eq 0) { throw 'No host(s) specified' }
  
  $portsInput = Get-Param $Params 'portPorts' '80,443'
  $timeout = [Math]::Min(30000, [Math]::Max(100, [int](Get-Param $Params 'portTimeout' 1000)))
  
  $ports = [System.Collections.Generic.List[int]]::new()
  foreach ($part in ($portsInput -split ',')) {
    $part = $part.Trim()
    if ($part -match '^(\d+)-(\d+)$') {
      $start = [int]$Matches[1]; $end = [int]$Matches[2]
      for ($p = $start; $p -le $end -and $ports.Count -lt 100; $p++) { $ports.Add($p) }
    } elseif ($part -match '^\d+$') {
      if ($ports.Count -lt 100) { $ports.Add([int]$part) }
    }
  }
  if ($ports.Count -eq 0) { throw 'No valid ports specified' }
  
  Write-XYProgress 0.2 "Scanning $($ports.Count) port(s) on $($hosts.Count) host(s)..."
  
  $commonPorts = @{
    20='FTP Data'; 21='FTP'; 22='SSH'; 23='Telnet'; 25='SMTP'; 53='DNS'; 80='HTTP'; 110='POP3'
    143='IMAP'; 443='HTTPS'; 465='SMTPS'; 587='SMTP Submission'; 993='IMAPS'; 995='POP3S'
    3306='MySQL'; 3389='RDP'; 5432='PostgreSQL'; 6379='Redis'; 8080='HTTP Proxy'; 8443='HTTPS Alt'
  }
  
  $allResults = [System.Collections.Generic.List[object]]::new()
  $totalWithOpen = 0
  
  $hostIndex = 0
  foreach ($host_ in $hosts) {
    $hostIndex++
    Write-XYProgress (0.2 + (0.7 * $hostIndex / $hosts.Count)) "Scanning $host_..."
    
    $results = [System.Collections.Generic.List[object]]::new()
    $openPorts = 0
    $closedPorts = 0
    
    foreach ($port in $ports) {
      $status = 'Closed'
      $service = if ($commonPorts.ContainsKey($port)) { $commonPorts[$port] } else { '-' }
      
      try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $result = $client.BeginConnect($host_, $port, $null, $null)
        $success = $result.AsyncWaitHandle.WaitOne($timeout, $false)
        if ($success -and $client.Connected) {
          $status = 'Open'
          $openPorts++
        } else { $closedPorts++ }
        $client.Close()
      } catch { $closedPorts++ }
      
      $results.Add([pscustomobject]@{ port=$port; status=$status; service=$service })
    }
    
    if ($openPorts -gt 0) { $totalWithOpen++ }
    
    $rows = @()
    foreach ($r in $results) { $rows += ,@($r.port, $r.status, $r.service) }
    Write-XY @{ table = @{ title="Port Scan - $host_"; header=@('Port','Status','Service'); rows=$rows; caption="$openPorts open, $closedPorts closed" } }
    
    $allResults.Add([pscustomobject]@{ host=$host_; portsScanned=$ports.Count; openPorts=$openPorts; closedPorts=$closedPorts; results=$results.ToArray() })
  }
  
  if ($hosts.Count -gt 1) {
    $summaryRows = @()
    foreach ($r in $allResults) {
      $status = if ($r.openPorts -gt 0) { 'OK' } else { 'CLOSED' }
      $summaryRows += ,@($r.host, $status, $r.openPorts, $r.closedPorts)
    }
    Write-XY @{ table = @{ title='Port Scan Summary'; header=@('Host','Status','Open','Closed'); rows=$summaryRows; caption="$totalWithOpen/$($hosts.Count) hosts with open ports" } }
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  [pscustomobject]@{ tool='Port Scanner'; hostsChecked=$hosts.Count; hostsWithOpenPorts=$totalWithOpen; timeout=$timeout; results=$allResults.ToArray() }
}

# ------------------------- HTTP Status Checker -------------------------
function Invoke-HttpChecker {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'httpSource' 'field'
  $urlsInput = $null
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'httpDataPath' ''
    $urlsInput = Get-NestedValue $inputData $path
    if ($null -eq $urlsInput) { throw "Data path '$path' not found in input data" }
  } else { $urlsInput = Get-Param $Params 'httpUrls' '' }
  
  $urls = @(Get-MultipleInputs $urlsInput 20)
  if ($urls.Count -eq 0) { throw 'No URL(s) specified' }
  
  $method = Get-Param $Params 'httpMethod' 'GET'
  $timeout = [Math]::Min(60, [Math]::Max(1, [int](Get-Param $Params 'httpTimeout' 10)))
  $followRedirects = if ($Params.PSObject.Properties.Name -contains 'httpFollowRedirects') { [bool]$Params.httpFollowRedirects } else { $true }
  
  Write-XYProgress 0.2 "Checking $($urls.Count) URL(s)..."
  
  $allResults = [System.Collections.Generic.List[object]]::new()
  $totalSuccess = 0
  $totalFail = 0
  
  $urlIndex = 0
  foreach ($url in $urls) {
    $urlIndex++
    if ($url -notmatch '^https?://') { $url = "https://$url" }
    Write-XYProgress (0.2 + (0.7 * $urlIndex / $urls.Count)) "Checking $url..."
    
    $statusCode = 0; $statusDesc = ''; $responseTime = 0; $headers = @{}
    $contentType = ''; $contentLength = 0; $server = ''; $redirectUrl = ''; $errorMsg = ''; $success = $true
    
    try {
      $handler = [System.Net.Http.HttpClientHandler]::new()
      $handler.AllowAutoRedirect = $followRedirects
      $client = [System.Net.Http.HttpClient]::new($handler)
      $client.Timeout = [TimeSpan]::FromSeconds($timeout)
      
      $sw = [System.Diagnostics.Stopwatch]::StartNew()
      $response = switch ($method) {
        'GET' { $client.GetAsync($url).Result }
        'HEAD' { $client.SendAsync([System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Head, $url)).Result }
        'POST' { $client.PostAsync($url, [System.Net.Http.StringContent]::new('')).Result }
        default { $client.GetAsync($url).Result }
      }
      $sw.Stop()
      $responseTime = $sw.ElapsedMilliseconds
      
      $statusCode = [int]$response.StatusCode
      $statusDesc = $response.ReasonPhrase
      
      foreach ($h in $response.Headers) { $headers[$h.Key] = ($h.Value -join ', ') }
      foreach ($h in $response.Content.Headers) { $headers[$h.Key] = ($h.Value -join ', ') }
      
      $contentType = if ($headers.ContainsKey('Content-Type')) { $headers['Content-Type'] } else { '-' }
      $contentLength = if ($headers.ContainsKey('Content-Length')) { [long]$headers['Content-Length'] } else { 0 }
      $server = if ($headers.ContainsKey('Server')) { $headers['Server'] } else { '-' }
      
      if (-not $followRedirects -and $statusCode -ge 300 -and $statusCode -lt 400) {
        $redirectUrl = if ($headers.ContainsKey('Location')) { $headers['Location'] } else { '-' }
      }
      
      $client.Dispose()
      $totalSuccess++
    } catch {
      $success = $false
      $errorMsg = $_.Exception.InnerException?.Message ?? $_.Exception.Message
      $totalFail++
    }
    
    $summaryRows = @(
      @('URL', $url), @('Method', $method),
      @('Status Code', $(if ($success) { "$statusCode $statusDesc" } else { 'Error' })),
      @('Response Time', "${responseTime}ms"), @('Server', $server)
    )
    if ($errorMsg) { $summaryRows += ,@('Error', $errorMsg) }
    
    Write-XY @{ table = @{ title="HTTP - $url"; header=@('Property','Value'); rows=$summaryRows; caption=$(if ($success) { 'Request completed' } else { 'Request failed' }) } }
    
    $allResults.Add([pscustomobject]@{ url=$url; method=$method; success=$success; statusCode=$statusCode; statusDescription=$statusDesc; responseTime=$responseTime; contentType=$contentType; server=$server; error=$errorMsg })
  }
  
  if ($urls.Count -gt 1) {
    $summaryRows = @()
    foreach ($r in $allResults) {
      $status = if ($r.success) { "$($r.statusCode)" } else { 'FAIL' }
      $summaryRows += ,@($r.url, $status, "$($r.responseTime)ms")
    }
    Write-XY @{ table = @{ title='HTTP Summary'; header=@('URL','Status','Response'); rows=$summaryRows; caption="$totalSuccess/$($urls.Count) requests successful" } }
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  [pscustomobject]@{ tool='HTTP Status Checker'; urlsChecked=$urls.Count; successful=$totalSuccess; failed=$totalFail; results=$allResults.ToArray() }
}

# ------------------------- SSL Certificate Checker -------------------------
function Invoke-SslChecker {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'sslSource' 'field'
  $hostsInput = $null
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'sslDataPath' ''
    $hostsInput = Get-NestedValue $inputData $path
    if ($null -eq $hostsInput) { throw "Data path '$path' not found in input data" }
  } else { $hostsInput = Get-Param $Params 'sslHosts' '' }
  
  $hosts = @(Get-MultipleInputs $hostsInput 20)
  if ($hosts.Count -eq 0) { throw 'No host(s) specified' }
  
  Write-XYProgress 0.2 "Checking SSL certificates for $($hosts.Count) host(s)..."
  
  $allResults = [System.Collections.Generic.List[object]]::new()
  $totalSuccess = 0
  $totalFail = 0
  
  $hostIndex = 0
  foreach ($hostEntry in $hosts) {
    $hostIndex++
    $host_ = $hostEntry -replace '^https?://', '' -replace '/.*$', ''
    $port = 443
    if ($host_ -match '^(.+):(\d+)$') { $host_ = $Matches[1]; $port = [int]$Matches[2] }
    
    Write-XYProgress (0.2 + (0.7 * $hostIndex / $hosts.Count)) "Checking $host_`:$port..."
    
    $cert = $null; $chain = $null; $success = $true; $errorMsg = ''
    
    try {
      $client = [System.Net.Sockets.TcpClient]::new($host_, $port)
      $sslStream = [System.Net.Security.SslStream]::new($client.GetStream(), $false, { $true })
      $sslStream.AuthenticateAsClient($host_)
      $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($sslStream.RemoteCertificate)
      $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
      $chain.Build($cert) | Out-Null
      $sslStream.Close(); $client.Close()
      $totalSuccess++
    } catch {
      $success = $false
      $errorMsg = $_.Exception.InnerException?.Message ?? $_.Exception.Message
      $totalFail++
    }
    
    if ($success -and $cert) {
      $now = [DateTime]::UtcNow
      $notAfter = $cert.NotAfter.ToUniversalTime()
      $daysUntilExpiry = [Math]::Floor(($notAfter - $now).TotalDays)
      $isExpired = $now -gt $notAfter
      $cn = ''; if ($cert.Subject -match 'CN=([^,]+)') { $cn = $Matches[1] }
      $validity = if ($isExpired) { 'EXPIRED' } elseif ($daysUntilExpiry -le 30) { 'EXPIRING SOON' } else { 'Valid' }
      
      $summaryRows = @(
        @('Host', "$host_`:$port"), @('Common Name', $cn),
        @('Valid Until', $notAfter.ToString('yyyy-MM-dd')), @('Days Until Expiry', $daysUntilExpiry), @('Status', $validity)
      )
      Write-XY @{ table = @{ title="SSL - $host_"; header=@('Property','Value'); rows=$summaryRows; caption=$validity } }
      
      $allResults.Add([pscustomobject]@{ host="$host_`:$port"; success=$true; commonName=$cn; validUntil=$notAfter; daysUntilExpiry=$daysUntilExpiry; isExpired=$isExpired; validity=$validity })
    } else {
      Write-XY @{ table = @{ title="SSL - $host_"; header=@('Property','Value'); rows=@(@('Host', "$host_`:$port"), @('Error', $errorMsg)); caption='Failed' } }
      $allResults.Add([pscustomobject]@{ host="$host_`:$port"; success=$false; error=$errorMsg })
    }
  }
  
  if ($hosts.Count -gt 1) {
    $summaryRows = @()
    foreach ($r in $allResults) {
      $status = if ($r.success) { $r.validity } else { 'FAIL' }
      $days = if ($r.success) { $r.daysUntilExpiry } else { '-' }
      $summaryRows += ,@($r.host, $status, $days)
    }
    Write-XY @{ table = @{ title='SSL Summary'; header=@('Host','Status','Days Left'); rows=$summaryRows; caption="$totalSuccess/$($hosts.Count) certificates retrieved" } }
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  [pscustomobject]@{ tool='SSL Certificate Checker'; hostsChecked=$hosts.Count; successful=$totalSuccess; failed=$totalFail; results=$allResults.ToArray() }
}

# ------------------------- NTP Check -------------------------
function Invoke-NtpCheck {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'ntpSource' 'field'
  $serversInput = $null
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'ntpDataPath' ''
    $serversInput = Get-NestedValue $inputData $path
    if ($null -eq $serversInput) { throw "Data path '$path' not found in input data" }
  } else { $serversInput = Get-Param $Params 'ntpServers' '' }
  
  $timeout = [Math]::Min(10000, [Math]::Max(500, [int](Get-Param $Params 'ntpTimeout' 3000)))
  
  # Parse servers using common function
  $servers = @(Get-MultipleInputs $serversInput 10)
  if ($servers.Count -eq 0) { throw 'No valid NTP servers specified' }
  
  Write-XYProgress 0.2 "Checking $($servers.Count) NTP server(s)..."
  
  $results = [System.Collections.Generic.List[object]]::new()
  $successCount = 0
  $failCount = 0
  
  # NTP epoch starts at 1900-01-01, Unix epoch at 1970-01-01
  $ntpEpochDiff = [uint64]2208988800
  
  $serverIndex = 0
  foreach ($server in $servers) {
    $serverIndex++
    Write-XYProgress (0.2 + (0.7 * $serverIndex / $servers.Count)) "Querying $server..."
    
    $serverResult = [ordered]@{
      server = $server
      success = $false
      responseTime = $null
      offset = $null
      stratum = $null
      referenceId = $null
      serverTime = $null
      localTime = $null
      error = $null
    }
    
    try {
      # Resolve hostname to IP
      $ip = [System.Net.Dns]::GetHostAddresses($server) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
      if (-not $ip) { throw "Could not resolve hostname" }
      
      # Create UDP client
      $udp = [System.Net.Sockets.UdpClient]::new()
      $udp.Client.ReceiveTimeout = $timeout
      $udp.Client.SendTimeout = $timeout
      $endpoint = [System.Net.IPEndPoint]::new($ip, 123)
      
      # Build NTP request packet (48 bytes)
      # LI=0, VN=4, Mode=3 (client) => 0x23
      $ntpData = [byte[]]::new(48)
      $ntpData[0] = 0x23
      
      # Record time before sending
      $sw = [System.Diagnostics.Stopwatch]::StartNew()
      $t1 = [DateTime]::UtcNow
      
      # Send request
      $udp.Connect($endpoint)
      $udp.Send($ntpData, $ntpData.Length) | Out-Null
      
      # Receive response
      $remoteEP = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
      $response = $udp.Receive([ref]$remoteEP)
      $sw.Stop()
      $t4 = [DateTime]::UtcNow
      
      $udp.Close()
      
      if ($response.Length -lt 48) { throw "Invalid NTP response (too short)" }
      
      # Parse response
      $li = ($response[0] -band 0xC0) -shr 6
      $vn = ($response[0] -band 0x38) -shr 3
      $mode = $response[0] -band 0x07
      $stratum = $response[1]
      $poll = $response[2]
      $precision = $response[3]
      
      # Reference ID (4 bytes at offset 12)
      $refId = ''
      if ($stratum -eq 0 -or $stratum -eq 1) {
        # Stratum 0/1: ASCII identifier
        $refId = [System.Text.Encoding]::ASCII.GetString($response, 12, 4).Trim([char]0)
      } else {
        # Stratum 2+: IP address of reference server
        $refId = "$($response[12]).$($response[13]).$($response[14]).$($response[15])"
      }
      
      # Transmit timestamp (seconds at offset 40, fraction at 44)
      $txSeconds = ([uint64]$response[40] -shl 24) -bor ([uint64]$response[41] -shl 16) -bor ([uint64]$response[42] -shl 8) -bor [uint64]$response[43]
      $txFraction = ([uint64]$response[44] -shl 24) -bor ([uint64]$response[45] -shl 16) -bor ([uint64]$response[46] -shl 8) -bor [uint64]$response[47]
      
      # Convert NTP timestamp to DateTime
      $txUnix = [double]($txSeconds - $ntpEpochDiff) + ([double]$txFraction / [math]::Pow(2, 32))
      $serverDateTime = [DateTimeOffset]::FromUnixTimeSeconds([long][math]::Floor($txUnix)).UtcDateTime.AddTicks([long](($txUnix % 1) * 10000000))
      
      # Calculate offset (simplified: server time - local time at reception)
      $offsetMs = ($serverDateTime - $t4).TotalMilliseconds
      
      # Stratum description
      $stratumDesc = switch ($stratum) {
        0 { 'Unspecified/Invalid' }
        1 { 'Primary (GPS, atomic clock)' }
        { $_ -ge 2 -and $_ -le 15 } { "Secondary (stratum $stratum)" }
        16 { 'Unsynchronized' }
        default { "Reserved ($stratum)" }
      }
      
      $serverResult.success = $true
      $serverResult.responseTime = $sw.ElapsedMilliseconds
      $serverResult.offset = [Math]::Round($offsetMs, 2)
      $serverResult.stratum = $stratum
      $serverResult.stratumDesc = $stratumDesc
      $serverResult.referenceId = $refId
      $serverResult.serverTime = $serverDateTime.ToString('yyyy-MM-dd HH:mm:ss.fff UTC')
      $serverResult.localTime = $t4.ToString('yyyy-MM-dd HH:mm:ss.fff UTC')
      $serverResult.version = $vn
      $serverResult.leapIndicator = $li
      $successCount++
    } catch {
      $serverResult.error = $_.Exception.Message
      $failCount++
    }
    
    $results.Add([pscustomobject]$serverResult)
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  # Build output tables
  foreach ($r in $results) {
    if ($r.success) {
      $rows = @(
        @('Server', $r.server),
        @('Status', 'OK - Reachable'),
        @('Response Time', "$($r.responseTime)ms"),
        @('Server Time', $r.serverTime),
        @('Local Time', $r.localTime),
        @('Offset', "$($r.offset)ms"),
        @('Stratum', "$($r.stratum) - $($r.stratumDesc)"),
        @('Reference ID', $r.referenceId),
        @('NTP Version', $r.version)
      )
      $offsetStatus = if ([Math]::Abs($r.offset) -lt 100) { 'Time is in sync' } elseif ([Math]::Abs($r.offset) -lt 1000) { 'Minor time drift detected' } else { 'Significant time drift!' }
      Write-XY @{ table = @{ title="NTP Server - $($r.server)"; header=@('Property','Value'); rows=$rows; caption=$offsetStatus } }
    } else {
      $rows = @(
        @('Server', $r.server),
        @('Status', 'FAIL - Unreachable'),
        @('Error', $r.error)
      )
      Write-XY @{ table = @{ title="NTP Server - $($r.server)"; header=@('Property','Value'); rows=$rows; caption='Failed to query NTP server' } }
    }
  }
  
  # Summary table if multiple servers
  if ($servers.Count -gt 1) {
    $summaryRows = @()
    foreach ($r in $results) {
      $status = if ($r.success) { 'OK' } else { 'FAIL' }
      $offset = if ($r.success) { "$($r.offset)ms" } else { '-' }
      $stratum = if ($r.success) { $r.stratum } else { '-' }
      $rtt = if ($r.success) { "$($r.responseTime)ms" } else { '-' }
      $summaryRows += ,@($r.server, $status, $rtt, $offset, $stratum)
    }
    Write-XY @{ table = @{ title='NTP Summary'; header=@('Server','Status','Response','Offset','Stratum'); rows=$summaryRows; caption="$successCount/$($servers.Count) servers reachable" } }
  }
  
  # Throw error if all servers failed
  if ($successCount -eq 0) {
    throw "NTP check failed: All $($servers.Count) server(s) unreachable"
  }
  
  [pscustomobject]@{ tool='NTP Check'; serversChecked=$servers.Count; successful=$successCount; failed=$failCount; results=$results.ToArray() }
}

# ------------------------- WHOIS Lookup -------------------------
function Invoke-WhoisLookup {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'whoisSource' 'field'
  $domainsInput = $null
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'whoisDataPath' ''
    $domainsInput = Get-NestedValue $inputData $path
    if ($null -eq $domainsInput) { throw "Data path '$path' not found in input data" }
  } else { $domainsInput = Get-Param $Params 'whoisDomains' '' }
  
  $domains = @(Get-MultipleInputs $domainsInput 10)
  if ($domains.Count -eq 0) { throw 'No domain(s) specified' }
  
  # Clean domains
  $domains = $domains | ForEach-Object { $_ -replace '^https?://', '' -replace '/.*$', '' -replace '^www\.', '' }
  
  Write-XYProgress 0.2 "Looking up WHOIS for $($domains.Count) domain(s)..."
  
  $whoisServers = @{
    'com'='whois.verisign-grs.com'; 'net'='whois.verisign-grs.com'; 'org'='whois.pir.org'
    'io'='whois.nic.io'; 'co'='whois.nic.co'; 'me'='whois.nic.me'; 'info'='whois.afilias.net'
    'biz'='whois.biz'; 'dev'='whois.nic.google'; 'app'='whois.nic.google'; 'uk'='whois.nic.uk'
    'de'='whois.denic.de'; 'fr'='whois.nic.fr'; 'nl'='whois.domain-registry.nl'; 'eu'='whois.eu'; 'au'='whois.auda.org.au'
  }
  
  $allResults = [System.Collections.Generic.List[object]]::new()
  $totalSuccess = 0
  $totalFail = 0
  
  $domainIndex = 0
  foreach ($domain in $domains) {
    $domainIndex++
    Write-XYProgress (0.2 + (0.7 * $domainIndex / $domains.Count)) "Looking up $domain..."
    
    $whoisData = @{}; $rawResponse = ''; $success = $true; $errorMsg = ''
    
    try {
      $tld = ($domain -split '\.')[-1].ToLower()
      $whoisServer = if ($whoisServers.ContainsKey($tld)) { $whoisServers[$tld] } else { 'whois.iana.org' }
      
      $client = [System.Net.Sockets.TcpClient]::new($whoisServer, 43)
      $stream = $client.GetStream(); $writer = [System.IO.StreamWriter]::new($stream); $reader = [System.IO.StreamReader]::new($stream)
      $writer.WriteLine($domain); $writer.Flush(); $rawResponse = $reader.ReadToEnd()
      $reader.Close(); $writer.Close(); $client.Close()
      
      $patterns = @{ 'Registrar'='Registrar:\s*(.+)'; 'Expiration Date'='(Expir[ey]|Registry Expiry Date).*?:\s*(.+)' }
      foreach ($key in $patterns.Keys) {
        $regMatches = [regex]::Matches($rawResponse, $patterns[$key], 'IgnoreCase,Multiline')
        if ($regMatches.Count -gt 0) { $whoisData[$key] = ($regMatches | ForEach-Object { $_.Groups[$_.Groups.Count - 1].Value.Trim() } | Select-Object -First 1) }
      }
      $totalSuccess++
    } catch {
      $success = $false
      $errorMsg = $_.Exception.Message
      $totalFail++
    }
    
    if ($success) {
      $summaryRows = @(@('Domain', $domain))
      if ($whoisData['Registrar']) { $summaryRows += ,@('Registrar', $whoisData['Registrar']) }
      if ($whoisData['Expiration Date']) { $summaryRows += ,@('Expiration', $whoisData['Expiration Date']) }
      Write-XY @{ table = @{ title="WHOIS - $domain"; header=@('Property','Value'); rows=$summaryRows; caption='Lookup successful' } }
      $allResults.Add([pscustomobject]@{ domain=$domain; success=$true; registrar=$whoisData['Registrar']; expirationDate=$whoisData['Expiration Date'] })
    } else {
      Write-XY @{ table = @{ title="WHOIS - $domain"; header=@('Property','Value'); rows=@(@('Domain', $domain), @('Error', $errorMsg)); caption='Lookup failed' } }
      $allResults.Add([pscustomobject]@{ domain=$domain; success=$false; error=$errorMsg })
    }
  }
  
  if ($domains.Count -gt 1) {
    $summaryRows = @()
    foreach ($r in $allResults) {
      $status = if ($r.success) { 'OK' } else { 'FAIL' }
      $expiry = if ($r.success -and $r.expirationDate) { $r.expirationDate.Substring(0, [Math]::Min(10, $r.expirationDate.Length)) } else { '-' }
      $summaryRows += ,@($r.domain, $status, $expiry)
    }
    Write-XY @{ table = @{ title='WHOIS Summary'; header=@('Domain','Status','Expiry'); rows=$summaryRows; caption="$totalSuccess/$($domains.Count) lookups successful" } }
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  [pscustomobject]@{ tool='WHOIS Lookup'; domainsChecked=$domains.Count; successful=$totalSuccess; failed=$totalFail; results=$allResults.ToArray() }
}

# ------------------------- Network Scanner -------------------------
function Invoke-NetworkScanner {
  param($Params, $JobInput)
  Write-XYProgress 0.05 'Validating parameters...'
  
  $source = Get-Param $Params 'netScanSource' 'field'
  $networksInput = $null
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'netScanDataPath' ''
    $networksInput = Get-NestedValue $inputData $path
    if ($null -eq $networksInput) { throw "Data path '$path' not found in input data" }
  } else { $networksInput = Get-Param $Params 'netScanNetworks' '' }
  
  $networks = @(Get-MultipleInputs $networksInput 10)
  if ($networks.Count -eq 0) { throw 'No network(s) specified' }
  
  $timeout = [Math]::Min(5000, [Math]::Max(100, [int](Get-Param $Params 'netScanTimeout' 500)))
  $maxConcurrent = 25
  $commonPorts = @(22, 80, 443, 3389, 445)
  
  # Helper: Convert CIDR to IP list
  function Get-IPsFromCIDR {
    param([string]$CIDR)
    if ($CIDR -notmatch '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$') {
      throw "Invalid CIDR format: $CIDR (expected format: 192.168.1.0/24)"
    }
    $ipPart = $Matches[1]
    $prefix = [int]$Matches[2]
    
    if ($prefix -lt 22) { throw "Network too large: /$prefix. Maximum allowed is /22 (1024 hosts)" }
    if ($prefix -gt 32) { throw "Invalid prefix: /$prefix" }
    
    $ipBytes = [System.Net.IPAddress]::Parse($ipPart).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)
    
    $hostBits = 32 - $prefix
    $numHosts = [Math]::Pow(2, $hostBits)
    $networkInt = $ipInt -band ([uint32]::MaxValue -shl $hostBits)
    
    $ips = [System.Collections.Generic.List[string]]::new()
    for ($i = 1; $i -lt ($numHosts - 1); $i++) {
      $currentInt = $networkInt + $i
      $bytes = [BitConverter]::GetBytes([uint32]$currentInt)
      [Array]::Reverse($bytes)
      $ips.Add(([System.Net.IPAddress]::new($bytes)).ToString())
    }
    return $ips
  }
  
  # Helper: Check single host (ping + port fallback)
  $checkHostScript = {
    param($IP, $Timeout, $Ports)
    $result = @{ IP = $IP; Active = $false; Method = ''; ResponseTime = $null; Hostname = ''; MAC = '' }
    
    # Try ping first
    try {
      $pinger = [System.Net.NetworkInformation.Ping]::new()
      $reply = $pinger.Send($IP, $Timeout)
      if ($reply.Status -eq 'Success') {
        $result.Active = $true
        $result.Method = 'ICMP'
        $result.ResponseTime = $reply.RoundtripTime
      }
      $pinger.Dispose()
    } catch { }
    
    # If ping failed, try common ports
    if (-not $result.Active) {
      foreach ($port in $Ports) {
        try {
          $client = [System.Net.Sockets.TcpClient]::new()
          $task = $client.BeginConnect($IP, $port, $null, $null)
          $success = $task.AsyncWaitHandle.WaitOne($Timeout, $false)
          if ($success -and $client.Connected) {
            $result.Active = $true
            $result.Method = "TCP/$port"
            $client.Close()
            break
          }
          $client.Close()
        } catch { }
      }
    }
    
    # Resolve hostname if active
    if ($result.Active) {
      try {
        $hostEntry = [System.Net.Dns]::GetHostEntry($IP)
        $result.Hostname = $hostEntry.HostName
      } catch { $result.Hostname = '-' }
    }
    
    return $result
  }
  
  Write-XYProgress 0.1 "Parsing $($networks.Count) network(s)..."
  
  $allResults = [System.Collections.Generic.List[object]]::new()
  $grandTotalActive = 0
  $grandTotalScanned = 0
  
  $networkIndex = 0
  foreach ($network in $networks) {
    $networkIndex++
    Write-XYProgress (0.1 + (0.05 * $networkIndex / $networks.Count)) "Parsing $network..."
    
    $networkResult = @{ network = $network; hosts = [System.Collections.Generic.List[object]]::new(); error = $null }
    
    try {
      $ips = @(Get-IPsFromCIDR $network)
      $totalIPs = $ips.Count
      $grandTotalScanned += $totalIPs
      
      Write-XYProgress 0.15 "Scanning $totalIPs hosts in $network (25 concurrent)..."
      
      # Create runspace pool for parallel execution
      $runspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $maxConcurrent)
      $runspacePool.Open()
      
      $jobs = [System.Collections.Generic.List[object]]::new()
      
      # Queue all IP scans
      foreach ($ip in $ips) {
        $ps = [PowerShell]::Create().AddScript($checkHostScript).AddArgument($ip).AddArgument($timeout).AddArgument($commonPorts)
        $ps.RunspacePool = $runspacePool
        $jobs.Add(@{ PS = $ps; Handle = $ps.BeginInvoke(); IP = $ip })
      }
      
      # Collect results with progress updates
      $completed = 0
      $activeCount = 0
      $hostResults = [System.Collections.Generic.List[object]]::new()
      
      foreach ($job in $jobs) {
        try {
          $r = $job.PS.EndInvoke($job.Handle)
          if ($r -and $r.Active) {
            $activeCount++
            $hostResults.Add([pscustomobject]$r)
          }
        } catch { }
        $job.PS.Dispose()
        $completed++
        
        if ($completed % 50 -eq 0 -or $completed -eq $totalIPs) {
          $pct = 0.15 + (0.75 * ($networkIndex - 1 + ($completed / $totalIPs)) / $networks.Count)
          Write-XYProgress $pct "Scanned $completed/$totalIPs in $network ($activeCount active)..."
        }
      }
      
      $runspacePool.Close()
      $runspacePool.Dispose()
      
      # Try to get MAC addresses from ARP cache (local subnet only)
      try {
        $arpOutput = & arp -a 2>$null
        $arpTable = @{}
        foreach ($line in $arpOutput) {
          if ($line -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F:-]{11,17})') {
            $arpTable[$Matches[1]] = $Matches[2].ToUpper() -replace '-', ':'
          }
        }
        foreach ($h in $hostResults) {
          if ($arpTable.ContainsKey($h.IP)) { $h.MAC = $arpTable[$h.IP] }
          else { $h.MAC = '-' }
        }
      } catch { }
      
      $grandTotalActive += $activeCount
      $networkResult.hosts = $hostResults
      $networkResult.totalScanned = $totalIPs
      $networkResult.activeCount = $activeCount
      
      # Output table for this network
      if ($hostResults.Count -gt 0) {
        $rows = @()
        foreach ($h in ($hostResults | Sort-Object { [System.Version]$_.IP })) {
          $rt = if ($null -ne $h.ResponseTime) { "$($h.ResponseTime)ms" } else { '-' }
          $rows += ,@($h.IP, $h.Hostname, $h.Method, $rt, $h.MAC)
        }
        Write-XY @{ table = @{ title="Active Hosts - $network"; header=@('IP','Hostname','Method','Response','MAC'); rows=$rows; caption="$activeCount active hosts found" } }
      } else {
        Write-XY @{ table = @{ title="Network Scan - $network"; header=@('Result'); rows=@(,@('No active hosts found')); caption="Scanned $totalIPs hosts" } }
      }
      
    } catch {
      $networkResult.error = $_.Exception.Message
      Write-XY @{ table = @{ title="Network Scan - $network"; header=@('Error'); rows=@(,@($_.Exception.Message)); caption='Scan failed' } }
    }
    
    $allResults.Add([pscustomobject]$networkResult)
  }
  
  # Summary if multiple networks
  if ($networks.Count -gt 1) {
    $summaryRows = @()
    foreach ($r in $allResults) {
      $status = if ($r.error) { 'ERROR' } else { 'OK' }
      $active = if ($r.error) { '-' } else { $r.activeCount }
      $scanned = if ($r.error) { '-' } else { $r.totalScanned }
      $summaryRows += ,@($r.network, $status, $scanned, $active)
    }
    Write-XY @{ table = @{ title='Network Scan Summary'; header=@('Network','Status','Scanned','Active'); rows=$summaryRows; caption="Total: $grandTotalActive active hosts in $grandTotalScanned scanned" } }
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  # Build output with all active hosts for easy bucket use
  $allActiveHosts = @()
  $allActiveIPs = @()
  foreach ($r in $allResults) {
    if ($r.hosts) {
      foreach ($h in $r.hosts) {
        $allActiveHosts += $h
        $allActiveIPs += $h.IP
      }
    }
  }
  
  [pscustomobject]@{
    tool = 'Network Scanner'
    networksScanned = $networks.Count
    totalHostsScanned = $grandTotalScanned
    totalActiveHosts = $grandTotalActive
    activeIPs = $allActiveIPs
    results = $allResults.ToArray()
    hosts = $allActiveHosts
  }
}

# ------------------------- Wake-on-LAN -------------------------
function Invoke-WakeOnLan {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'wolSource' 'field'
  $devicesInput = $null
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'wolDataPath' ''
    $devicesInput = Get-NestedValue $inputData $path
    if ($null -eq $devicesInput) { throw "Data path '$path' not found in input data" }
  } else { $devicesInput = Get-Param $Params 'wolMacAddresses' '' }
  
  $devices = @(Get-MultipleInputs $devicesInput 50)
  if ($devices.Count -eq 0) { throw 'No device(s) specified' }
  
  $broadcastIP = Get-Param $Params 'wolBroadcast' '255.255.255.255'
  $port = [int](Get-Param $Params 'wolPort' 9)
  
  Write-XYProgress 0.2 "Sending Wake-on-LAN to $($devices.Count) device(s)..."
  
  $results = [System.Collections.Generic.List[object]]::new()
  $successCount = 0
  
  foreach ($device in $devices) {
    $mac = $device.Trim().ToUpper() -replace '[:-]', ''
    $success = $false
    $errorMsg = ''
    
    try {
      if ($mac -notmatch '^[0-9A-F]{12}$') { throw "Invalid MAC format: $device" }
      
      # Build magic packet: 6x FF + 16x MAC
      $macBytes = [byte[]]::new(6)
      for ($i = 0; $i -lt 6; $i++) { $macBytes[$i] = [Convert]::ToByte($mac.Substring($i * 2, 2), 16) }
      
      $packet = [byte[]]::new(102)
      for ($i = 0; $i -lt 6; $i++) { $packet[$i] = 0xFF }
      for ($i = 0; $i -lt 16; $i++) { [Array]::Copy($macBytes, 0, $packet, 6 + ($i * 6), 6) }
      
      $udpClient = [System.Net.Sockets.UdpClient]::new()
      $udpClient.EnableBroadcast = $true
      $udpClient.Send($packet, $packet.Length, $broadcastIP, $port) | Out-Null
      $udpClient.Close()
      
      $success = $true
      $successCount++
    } catch {
      $errorMsg = $_.Exception.Message
    }
    
    $formattedMac = ($mac -replace '(.{2})', '$1:').TrimEnd(':')
    $results.Add([pscustomobject]@{ mac = $formattedMac; sent = $success; error = $errorMsg })
  }
  
  # Output table
  $rows = @()
  foreach ($r in $results) {
    $status = if ($r.sent) { 'Sent' } else { "Failed: $($r.error)" }
    $rows += ,@($r.mac, $status)
  }
  Write-XY @{ table = @{ title='Wake-on-LAN Results'; header=@('MAC Address','Status'); rows=$rows; caption="$successCount/$($devices.Count) packets sent to $broadcastIP`:$port" } }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  [pscustomobject]@{ tool='Wake-on-LAN'; deviceCount=$devices.Count; sent=$successCount; broadcast=$broadcastIP; port=$port; results=$results.ToArray() }
}

# ------------------------- Subnet Calculator -------------------------
function Invoke-SubnetCalculator {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $mode = Get-Param $Params 'subnetMode' 'calculate'
  $cidrInput = Get-Param $Params 'subnetCidr' ''
  
  if (-not $cidrInput) { throw 'No network/CIDR specified' }
  
  Write-XYProgress 0.3 'Calculating subnet details...'
  
  # Helper functions
  function ConvertTo-IPInt { param([string]$IP) $b = [System.Net.IPAddress]::Parse($IP).GetAddressBytes(); [Array]::Reverse($b); [BitConverter]::ToUInt32($b, 0) }
  function ConvertTo-IPString { param([uint32]$Int) $b = [BitConverter]::GetBytes($Int); [Array]::Reverse($b); ([System.Net.IPAddress]::new($b)).ToString() }
  function ConvertTo-Binary { param([string]$IP) ($IP -split '\.' | ForEach-Object { [Convert]::ToString([int]$_, 2).PadLeft(8, '0') }) -join '.' }
  
  $result = @{ tool = 'Subnet Calculator'; mode = $mode }
  
  if ($mode -eq 'vlsm') {
    # VLSM mode: split network into subnets
    $vlsmInput = Get-Param $Params 'subnetVlsmRequirements' ''
    if (-not $vlsmInput) { throw 'No VLSM host requirements specified' }
    
    if ($cidrInput -notmatch '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$') { throw 'Invalid CIDR format' }
    $baseIP = $Matches[1]; $basePrefix = [int]$Matches[2]
    $baseInt = ConvertTo-IPInt $baseIP
    $totalHosts = [Math]::Pow(2, 32 - $basePrefix)
    
    # Parse host requirements (comma-separated)
    $requirements = @($vlsmInput -split '[,;\n]+' | ForEach-Object { [int]$_.Trim() } | Where-Object { $_ -gt 0 } | Sort-Object -Descending)
    
    $subnets = [System.Collections.Generic.List[object]]::new()
    $currentInt = $baseInt
    $usedHosts = 0
    
    foreach ($needed in $requirements) {
      $hostBits = [Math]::Ceiling([Math]::Log($needed + 2, 2))
      $subnetSize = [Math]::Pow(2, $hostBits)
      $prefix = 32 - $hostBits
      
      if ($usedHosts + $subnetSize -gt $totalHosts) {
        $subnets.Add([pscustomobject]@{ network = 'INSUFFICIENT SPACE'; prefix = '-'; hosts = $needed; usable = '-' })
        continue
      }
      
      $networkAddr = ConvertTo-IPString $currentInt
      $broadcast = ConvertTo-IPString ($currentInt + $subnetSize - 1)
      $firstHost = ConvertTo-IPString ($currentInt + 1)
      $lastHost = ConvertTo-IPString ($currentInt + $subnetSize - 2)
      
      $subnets.Add([pscustomobject]@{ network = "$networkAddr/$prefix"; needed = $needed; usable = ($subnetSize - 2); first = $firstHost; last = $lastHost; broadcast = $broadcast })
      
      $currentInt += $subnetSize
      $usedHosts += $subnetSize
    }
    
    $rows = @()
    foreach ($s in $subnets) { $rows += ,@($s.network, $s.needed, $s.usable, $s.first, $s.last) }
    Write-XY @{ table = @{ title="VLSM Subnets for $cidrInput"; header=@('Subnet','Needed','Usable','First Host','Last Host'); rows=$rows; caption="$($subnets.Count) subnets created" } }
    
    $result.subnets = $subnets.ToArray()
  }
  else {
    # Standard calculate mode
    if ($cidrInput -notmatch '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$') { throw 'Invalid CIDR format' }
    $ip = $Matches[1]; $prefix = [int]$Matches[2]
    
    $ipInt = ConvertTo-IPInt $ip
    $hostBits = 32 - $prefix
    $numHosts = [Math]::Pow(2, $hostBits)
    $maskInt = [uint32]::MaxValue -shl $hostBits
    $networkInt = $ipInt -band $maskInt
    $broadcastInt = $networkInt + $numHosts - 1
    
    $networkAddr = ConvertTo-IPString $networkInt
    $broadcastAddr = ConvertTo-IPString $broadcastInt
    $firstHost = if ($numHosts -gt 2) { ConvertTo-IPString ($networkInt + 1) } else { 'N/A' }
    $lastHost = if ($numHosts -gt 2) { ConvertTo-IPString ($broadcastInt - 1) } else { 'N/A' }
    $subnetMask = ConvertTo-IPString $maskInt
    $wildcardMask = ConvertTo-IPString ([uint32]::MaxValue -bxor $maskInt)
    $usableHosts = if ($numHosts -gt 2) { $numHosts - 2 } else { 0 }
    
    $rows = @(
      @('CIDR Notation', $cidrInput),
      @('Network Address', $networkAddr),
      @('Broadcast Address', $broadcastAddr),
      @('Subnet Mask', $subnetMask),
      @('Wildcard Mask', $wildcardMask),
      @('First Usable Host', $firstHost),
      @('Last Usable Host', $lastHost),
      @('Total Addresses', $numHosts),
      @('Usable Hosts', $usableHosts),
      @('Network Binary', (ConvertTo-Binary $networkAddr)),
      @('Mask Binary', (ConvertTo-Binary $subnetMask))
    )
    Write-XY @{ table = @{ title='Subnet Details'; header=@('Property','Value'); rows=$rows; caption='' } }
    
    $result += @{ cidr=$cidrInput; network=$networkAddr; broadcast=$broadcastAddr; subnetMask=$subnetMask; wildcardMask=$wildcardMask; firstHost=$firstHost; lastHost=$lastHost; totalAddresses=$numHosts; usableHosts=$usableHosts }
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  [pscustomobject]$result
}

# ------------------------- IP Geolocation -------------------------
function Invoke-IPGeolocation {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'geoSource' 'field'
  $ipsInput = $null
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'geoDataPath' ''
    $ipsInput = Get-NestedValue $inputData $path
    if ($null -eq $ipsInput) { throw "Data path '$path' not found in input data" }
  } else { $ipsInput = Get-Param $Params 'geoIpAddresses' '' }
  
  $ips = @(Get-MultipleInputs $ipsInput 20)
  if ($ips.Count -eq 0) { throw 'No IP address(es) specified' }
  
  Write-XYProgress 0.2 "Looking up geolocation for $($ips.Count) IP(s)..."
  
  $results = [System.Collections.Generic.List[object]]::new()
  $ipIndex = 0
  
  foreach ($ip in $ips) {
    $ipIndex++
    Write-XYProgress (0.2 + (0.7 * $ipIndex / $ips.Count)) "Looking up $ip..."
    
    $geoData = @{ ip = $ip; success = $false }
    
    try {
      $response = Invoke-RestMethod -Uri "http://ip-api.com/json/$($ip)?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query" -TimeoutSec 10 -UserAgent 'xyOps-Network/1.0'
      
      if ($response.status -eq 'success') {
        $geoData.success = $true
        $geoData.country = $response.country
        $geoData.countryCode = $response.countryCode
        $geoData.region = $response.regionName
        $geoData.city = $response.city
        $geoData.zip = $response.zip
        $geoData.latitude = $response.lat
        $geoData.longitude = $response.lon
        $geoData.timezone = $response.timezone
        $geoData.isp = $response.isp
        $geoData.org = $response.org
        $geoData.asn = $response.as
        
        $rows = @(
          @('IP Address', $ip),
          @('Country', "$($response.country) ($($response.countryCode))"),
          @('Region', $response.regionName),
          @('City', $response.city),
          @('ZIP/Postal', $response.zip),
          @('Coordinates', "$($response.lat), $($response.lon)"),
          @('Timezone', $response.timezone),
          @('ISP', $response.isp),
          @('Organization', $response.org),
          @('ASN', $response.as)
        )
        Write-XY @{ table = @{ title="Geolocation - $ip"; header=@('Property','Value'); rows=$rows; caption='' } }
      } else {
        $geoData.error = $response.message
        Write-XY @{ table = @{ title="Geolocation - $ip"; header=@('Property','Value'); rows=@(@('Error', $response.message)); caption='Lookup failed' } }
      }
    } catch {
      $geoData.error = $_.Exception.Message
      Write-XY @{ table = @{ title="Geolocation - $ip"; header=@('Property','Value'); rows=@(@('Error', $_.Exception.Message)); caption='Lookup failed' } }
    }
    
    $results.Add([pscustomobject]$geoData)
    
    # Rate limit: ip-api allows 45 requests per minute for free
    if ($ipIndex -lt $ips.Count) { Start-Sleep -Milliseconds 1500 }
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  [pscustomobject]@{ tool='IP Geolocation'; ipsChecked=$ips.Count; results=$results.ToArray() }
}

# ------------------------- SPF/DKIM/DMARC Checker -------------------------
function Invoke-EmailAuthChecker {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'emailAuthSource' 'field'
  $domainsInput = $null
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'emailAuthDataPath' ''
    $domainsInput = Get-NestedValue $inputData $path
    if ($null -eq $domainsInput) { throw "Data path '$path' not found in input data" }
  } else { $domainsInput = Get-Param $Params 'emailAuthDomains' '' }
  
  $domains = @(Get-MultipleInputs $domainsInput 10)
  if ($domains.Count -eq 0) { throw 'No domain(s) specified' }
  
  $dkimSelector = Get-Param $Params 'emailAuthDkimSelector' 'default'
  $dnsMode = Get-Param $Params 'emailAuthDnsMode' 'internal'
  $externalDns = Get-Param $Params 'emailAuthExternalDns' '1.1.1.1'
  $dnsServer = if ($dnsMode -eq 'external') { $externalDns } else { $null }
  
  # Test external DNS connectivity if external mode is selected
  if ($dnsServer) {
    Write-XYProgress 0.15 "Testing connectivity to external DNS server $dnsServer..."
    try {
      $null = Resolve-DnsName -Name 'cloudflare.com' -Type A -Server $dnsServer -ErrorAction Stop -DnsOnly
    } catch {
      throw "Cannot reach external DNS server '$dnsServer'. A firewall rule may be required to allow outbound DNS (UDP/TCP port 53) to this server. Error: $($_.Exception.Message)"
    }
  }
  
  Write-XYProgress 0.2 "Checking email authentication for $($domains.Count) domain(s)$(if ($dnsServer) { " using DNS $dnsServer" } else { '' })..."
  
  $results = [System.Collections.Generic.List[object]]::new()
  
  foreach ($domain in $domains) {
    $domain = $domain -replace '^https?://', '' -replace '/.*$', '' -replace '^www\.', ''
    Write-XYProgress 0.3 "Checking $domain..."
    
    $domainResult = @{ domain = $domain; spf = @{}; dkim = @{}; dmarc = @{}; score = 0; grade = 'F'; recommendations = @() }
    $score = 0
    $recommendations = [System.Collections.Generic.List[string]]::new()
    
    # Check SPF
    try {
      $dnsParams = @{ Name = $domain; Type = 'TXT'; ErrorAction = 'Stop' }
      if ($dnsServer) { $dnsParams.Server = $dnsServer }
      $allRecords = @(Resolve-DnsName @dnsParams)
      $txtRecords = @($allRecords | Where-Object { $null -ne $_.Strings })
      $spfRecords = @()
      foreach ($rec in $txtRecords) {
        $txtValue = if ($rec.Strings -is [array]) { $rec.Strings -join '' } else { [string]$rec.Strings }
        if ($txtValue -match '^v=spf1') { $spfRecords += @{ record = $txtValue } }
      }
      
      if ($spfRecords.Count -gt 0) {
        $spfRecord = $spfRecords[0].record
        if ($spfRecords.Count -gt 1) { $recommendations.Add("SPF: WARNING - Multiple SPF records found ($($spfRecords.Count)). Only one SPF record should exist per domain!") }
        $domainResult.spf.exists = $true
        $domainResult.spf.record = $spfRecord
        $score += 25
        
        # Validate SPF
        if ($spfRecord -match '-all$') { $domainResult.spf.policy = 'Strict (-all)'; $score += 5 }
        elseif ($spfRecord -match '~all$') { $domainResult.spf.policy = 'Soft fail (~all)'; $score += 3 }
        elseif ($spfRecord -match '\?all$') { $domainResult.spf.policy = 'Neutral (?all)'; $recommendations.Add('SPF: Use -all or ~all instead of ?all') }
        elseif ($spfRecord -match '\+all$') { $domainResult.spf.policy = 'Allow all (+all)'; $recommendations.Add('SPF: CRITICAL - +all allows anyone to send as your domain!') }
        else { $recommendations.Add('SPF: Add -all or ~all at the end') }
        
        $lookups = ([regex]::Matches($spfRecord, '(include:|a:|mx:|ptr:|exists:)')).Count
        $domainResult.spf.lookups = $lookups
        if ($lookups -gt 10) { $recommendations.Add("SPF: Too many DNS lookups ($lookups/10 max)") }
      } else {
        $domainResult.spf.exists = $false
        $recommendations.Add('SPF: No SPF record found - add one to prevent spoofing')
      }
    } catch { $domainResult.spf.exists = $false; $domainResult.spf.error = $_.Exception.Message }
    
    # Check DKIM
    try {
      $dkimName = "$dkimSelector._domainkey.$domain"
      $dkimDnsParams = @{ Name = $dkimName; Type = 'TXT'; ErrorAction = 'Stop' }
      if ($dnsServer) { $dkimDnsParams.Server = $dnsServer }
      $dkimRecords = @(Resolve-DnsName @dkimDnsParams)
      if ($dkimRecords.Count -gt 0) {
        $dkimRecord = $dkimRecords[0].Strings -join ''
        $domainResult.dkim.exists = $true
        $domainResult.dkim.selector = $dkimSelector
        $domainResult.dkim.record = if ($dkimRecord.Length -gt 100) { $dkimRecord.Substring(0, 100) + '...' } else { $dkimRecord }
        $score += 25
        
        if ($dkimRecord -match 'k=rsa') { $domainResult.dkim.keyType = 'RSA' }
        if ($dkimRecord -match 'p=([A-Za-z0-9+/=]+)') {
          $keyLength = $Matches[1].Length * 6 / 8 * 8
          $domainResult.dkim.keyLength = "~$keyLength bits"
          if ($keyLength -lt 1024) { $recommendations.Add('DKIM: Key length should be at least 1024 bits') }
        }
      } else {
        $domainResult.dkim.exists = $false
        $recommendations.Add("DKIM: No record found for selector '$dkimSelector'")
      }
    } catch { $domainResult.dkim.exists = $false; $domainResult.dkim.error = 'Not found or error' }
    
    # Check DMARC
    try {
      $dmarcName = "_dmarc.$domain"
      $dmarcDnsParams = @{ Name = $dmarcName; Type = 'TXT'; ErrorAction = 'Stop' }
      if ($dnsServer) { $dmarcDnsParams.Server = $dnsServer }
      $dmarcTxtRecords = @(Resolve-DnsName @dmarcDnsParams | Where-Object { $_.QueryType -eq 'TXT' -and $null -ne $_.Strings })
      $dmarcRecords = @($dmarcTxtRecords | Where-Object { ($_.Strings -join '') -match '^v=DMARC1' })
      if ($dmarcRecords.Count -gt 0) {
        $dmarcRecord = $dmarcRecords[0].Strings -join ''
        $domainResult.dmarc.exists = $true
        $domainResult.dmarc.record = $dmarcRecord
        $score += 25
        
        if ($dmarcRecord -match 'p=(none|quarantine|reject)') {
          $policy = $Matches[1]
          $domainResult.dmarc.policy = $policy
          if ($policy -eq 'reject') { $score += 10 }
          elseif ($policy -eq 'quarantine') { $score += 5 }
          else { $recommendations.Add('DMARC: Consider upgrading policy from none to quarantine or reject') }
        }
        if ($dmarcRecord -match 'rua=([^;]+)') { $domainResult.dmarc.reportUri = $Matches[1]; $score += 5 }
        else { $recommendations.Add('DMARC: Add rua= to receive aggregate reports') }
        if ($dmarcRecord -match 'pct=(\d+)') { $domainResult.dmarc.percentage = [int]$Matches[1] }
      } else {
        $domainResult.dmarc.exists = $false
        $recommendations.Add('DMARC: No DMARC record found - add one for policy enforcement')
      }
    } catch { $domainResult.dmarc.exists = $false; $domainResult.dmarc.error = $_.Exception.Message }
    
    # Calculate grade
    $grade = if ($score -ge 90) { 'A' } elseif ($score -ge 75) { 'B' } elseif ($score -ge 60) { 'C' } elseif ($score -ge 40) { 'D' } else { 'F' }
    $domainResult.score = $score
    $domainResult.grade = $grade
    $domainResult.recommendations = $recommendations.ToArray()
    
    # Output tables
    $summaryRows = @(
      @('Domain', $domain),
      @('Score', "$score/100"),
      @('Grade', $grade),
      @('SPF', $(if ($domainResult.spf.exists) { 'Found' } else { 'Missing' })),
      @('DKIM', $(if ($domainResult.dkim.exists) { 'Found' } else { 'Missing' })),
      @('DMARC', $(if ($domainResult.dmarc.exists) { 'Found' } else { 'Missing' }))
    )
    Write-XY @{ table = @{ title="Email Auth Summary - $domain"; header=@('Property','Value'); rows=$summaryRows; caption="Grade: $grade" } }
    
    if ($domainResult.spf.exists) {
      Write-XY @{ table = @{ title="SPF Record"; header=@('Property','Value'); rows=@(@('Record', $domainResult.spf.record), @('Policy', $domainResult.spf.policy), @('DNS Lookups', $domainResult.spf.lookups)); caption='' } }
    }
    if ($domainResult.dmarc.exists) {
      Write-XY @{ table = @{ title="DMARC Record"; header=@('Property','Value'); rows=@(@('Record', $domainResult.dmarc.record), @('Policy', $domainResult.dmarc.policy)); caption='' } }
    }
    if ($recommendations.Count -gt 0) {
      $recRows = @(); foreach ($r in $recommendations) { $recRows += ,@($r) }
      Write-XY @{ table = @{ title="Recommendations"; header=@('Action'); rows=$recRows; caption='' } }
    }
    
    $results.Add([pscustomobject]$domainResult)
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  [pscustomobject]@{ tool='Email Auth Checker'; domainsChecked=$domains.Count; results=$results.ToArray() }
}

# ------------------------- Blacklist Checker -------------------------
function Invoke-BlacklistChecker {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'blSource' 'field'
  $targetsInput = $null
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'blDataPath' ''
    $targetsInput = Get-NestedValue $inputData $path
    if ($null -eq $targetsInput) { throw "Data path '$path' not found in input data" }
  } else { $targetsInput = Get-Param $Params 'blTargets' '' }
  
  $targets = @(Get-MultipleInputs $targetsInput 10)
  if ($targets.Count -eq 0) { throw 'No IP(s) or domain(s) specified' }
  
  Write-XYProgress 0.2 "Checking $($targets.Count) target(s) against blacklists..."
  
  # Common DNSBL servers
  $ipBlacklists = @(
    @{ name = 'Spamhaus ZEN'; zone = 'zen.spamhaus.org' },
    @{ name = 'Barracuda'; zone = 'b.barracudacentral.org' },
    @{ name = 'SpamCop'; zone = 'bl.spamcop.net' },
    @{ name = 'SORBS'; zone = 'dnsbl.sorbs.net' },
    @{ name = 'Composite BL'; zone = 'cbl.abuseat.org' },
    @{ name = 'UCEPROTECT-1'; zone = 'dnsbl-1.uceprotect.net' },
    @{ name = 'Spam Rats'; zone = 'noptr.spamrats.com' }
  )
  
  $domainBlacklists = @(
    @{ name = 'Spamhaus DBL'; zone = 'dbl.spamhaus.org' },
    @{ name = 'SURBL'; zone = 'multi.surbl.org' },
    @{ name = 'URIBL'; zone = 'multi.uribl.com' }
  )
  
  $results = [System.Collections.Generic.List[object]]::new()
  
  foreach ($target in $targets) {
    $target = $target.Trim()
    $isIP = $target -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    $targetResult = @{ target = $target; type = $(if ($isIP) { 'IP' } else { 'Domain' }); listings = @(); listedCount = 0; checkedCount = 0 }
    
    $blacklists = if ($isIP) { $ipBlacklists } else { $domainBlacklists }
    $queryTarget = if ($isIP) { ($target -split '\.' | ForEach-Object -Begin { $a = @() } -Process { $a = ,$_ + $a } -End { $a -join '.' }) } else { $target }
    
    foreach ($bl in $blacklists) {
      $targetResult.checkedCount++
      $query = "$queryTarget.$($bl.zone)"
      $listed = $false
      
      try {
        $result = Resolve-DnsName -Name $query -Type A -ErrorAction Stop 2>$null
        if ($result) { $listed = $true; $targetResult.listedCount++ }
      } catch { }
      
      $targetResult.listings += [pscustomobject]@{ blacklist = $bl.name; zone = $bl.zone; listed = $listed }
    }
    
    # Output table
    $rows = @()
    foreach ($l in $targetResult.listings) {
      $status = if ($l.listed) { 'LISTED' } else { 'Clean' }
      $rows += ,@($l.blacklist, $status)
    }
    $caption = if ($targetResult.listedCount -eq 0) { 'Not listed on any blacklist' } else { "LISTED on $($targetResult.listedCount) blacklist(s)!" }
    Write-XY @{ table = @{ title="Blacklist Check - $target"; header=@('Blacklist','Status'); rows=$rows; caption=$caption } }
    
    $results.Add([pscustomobject]$targetResult)
  }
  
  # Summary
  if ($targets.Count -gt 1) {
    $summaryRows = @()
    foreach ($r in $results) {
      $status = if ($r.listedCount -eq 0) { 'Clean' } else { "LISTED ($($r.listedCount))" }
      $summaryRows += ,@($r.target, $r.type, $status)
    }
    Write-XY @{ table = @{ title='Blacklist Summary'; header=@('Target','Type','Status'); rows=$summaryRows; caption='' } }
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  [pscustomobject]@{ tool='Blacklist Checker'; targetsChecked=$targets.Count; results=$results.ToArray() }
}

# ------------------------- SMTP Checker -------------------------
function Invoke-SmtpChecker {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'smtpSource' 'field'
  $serversInput = $null
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'smtpDataPath' ''
    $serversInput = Get-NestedValue $inputData $path
    if ($null -eq $serversInput) { throw "Data path '$path' not found in input data" }
  } else { $serversInput = Get-Param $Params 'smtpServers' '' }
  
  $servers = @(Get-MultipleInputs $serversInput 10)
  if ($servers.Count -eq 0) { throw 'No SMTP server(s) specified' }
  
  $port = [int](Get-Param $Params 'smtpPort' 25)
  $timeout = [int](Get-Param $Params 'smtpTimeout' 10000)
  $sendTest = [bool](Get-Param $Params 'smtpSendTest' $false)
  $testFrom = Get-Param $Params 'smtpTestFrom' ''
  $testTo = Get-Param $Params 'smtpTestTo' ''
  $authUser = Get-Param $Params 'smtpUsername' ''
  $authPass = Get-Param $Params 'smtpPassword' ''
  
  Write-XYProgress 0.2 "Checking $($servers.Count) SMTP server(s)..."
  
  $results = [System.Collections.Generic.List[object]]::new()
  
  foreach ($server in $servers) {
    $serverHost = $server -replace ':.*$', ''
    $serverPort = if ($server -match ':(\d+)$') { [int]$Matches[1] } else { $port }
    
    Write-XYProgress 0.3 "Checking $serverHost`:$serverPort..."
    
    $serverResult = @{
      server = $serverHost; port = $serverPort; success = $false
      banner = ''; starttls = $false; authMethods = @(); tlsVersion = ''; openRelay = 'Not tested'
      testMailSent = $false; error = ''
    }
    
    try {
      $client = [System.Net.Sockets.TcpClient]::new()
      $client.ReceiveTimeout = $timeout
      $client.SendTimeout = $timeout
      $client.Connect($serverHost, $serverPort)
      
      $stream = $client.GetStream()
      $reader = [System.IO.StreamReader]::new($stream)
      $writer = [System.IO.StreamWriter]::new($stream)
      $writer.AutoFlush = $true
      
      # Read banner
      $banner = $reader.ReadLine()
      $serverResult.banner = $banner
      $serverResult.success = $true
      
      # Send EHLO
      $writer.WriteLine("EHLO test.local")
      $ehloResponse = @()
      do {
        $line = $reader.ReadLine()
        $ehloResponse += $line
        
        if ($line -match 'STARTTLS') { $serverResult.starttls = $true }
        if ($line -match 'AUTH (.+)$') { $serverResult.authMethods = $Matches[1] -split '\s+' }
      } while ($line -match '^250-')
      
      # Try STARTTLS if available
      if ($serverResult.starttls -and $serverPort -ne 465) {
        $writer.WriteLine('STARTTLS')
        $starttlsResp = $reader.ReadLine()
        if ($starttlsResp -match '^220') {
          $sslStream = [System.Net.Security.SslStream]::new($stream, $false)
          $sslStream.AuthenticateAsClient($serverHost)
          $serverResult.tlsVersion = $sslStream.SslProtocol.ToString()
          $reader = [System.IO.StreamReader]::new($sslStream)
          $writer = [System.IO.StreamWriter]::new($sslStream)
          $writer.AutoFlush = $true
          
          # Re-EHLO after STARTTLS
          $writer.WriteLine("EHLO test.local")
          do { $line = $reader.ReadLine() } while ($line -match '^250-')
        }
      }
      
      # Test for open relay (if not sending test mail)
      if (-not $sendTest) {
        $writer.WriteLine('MAIL FROM:<test@example.com>')
        $mailResp = $reader.ReadLine()
        if ($mailResp -match '^250') {
          $writer.WriteLine('RCPT TO:<test@example.org>')
          $rcptResp = $reader.ReadLine()
          $serverResult.openRelay = if ($rcptResp -match '^250') { 'VULNERABLE!' } else { 'Protected' }
        }
        $writer.WriteLine('RSET')
        $reader.ReadLine() | Out-Null
      }
      
      # Send test mail if requested
      if ($sendTest -and $testFrom -and $testTo) {
        if ($authUser -and $authPass) {
          # Authenticate first
          $writer.WriteLine('AUTH LOGIN')
          $reader.ReadLine() | Out-Null
          $writer.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($authUser)))
          $reader.ReadLine() | Out-Null
          $writer.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($authPass)))
          $authResp = $reader.ReadLine()
          if ($authResp -notmatch '^235') { throw "Authentication failed: $authResp" }
        }
        
        $writer.WriteLine("MAIL FROM:<$testFrom>")
        $mailResp = $reader.ReadLine()
        if ($mailResp -match '^250') {
          $writer.WriteLine("RCPT TO:<$testTo>")
          $rcptResp = $reader.ReadLine()
          if ($rcptResp -match '^250') {
            $writer.WriteLine('DATA')
            $dataResp = $reader.ReadLine()
            if ($dataResp -match '^354') {
              $writer.WriteLine("From: $testFrom")
              $writer.WriteLine("To: $testTo")
              $writer.WriteLine("Subject: SMTP Test from xyOps")
              $writer.WriteLine("Date: $([DateTime]::UtcNow.ToString('r'))")
              $writer.WriteLine('')
              $writer.WriteLine('This is a test email sent by xyOps SMTP Checker.')
              $writer.WriteLine('.')
              $finalResp = $reader.ReadLine()
              $serverResult.testMailSent = $finalResp -match '^250'
            }
          }
        }
      }
      
      $writer.WriteLine('QUIT')
      $client.Close()
      
    } catch {
      $serverResult.error = $_.Exception.Message
    }
    
    # Output table
    $rows = @(
      @('Server', "$serverHost`:$serverPort"),
      @('Status', $(if ($serverResult.success) { 'Connected' } else { 'Failed' })),
      @('Banner', $(if ($serverResult.banner) { $serverResult.banner } else { '-' })),
      @('STARTTLS', $(if ($serverResult.starttls) { 'Supported' } else { 'Not available' })),
      @('TLS Version', $(if ($serverResult.tlsVersion) { $serverResult.tlsVersion } else { '-' })),
      @('Auth Methods', $(if ($serverResult.authMethods.Count -gt 0) { $serverResult.authMethods -join ', ' } else { 'None' })),
      @('Open Relay', $serverResult.openRelay)
    )
    if ($sendTest) { $rows += ,@('Test Mail', $(if ($serverResult.testMailSent) { 'Sent successfully' } else { 'Not sent' })) }
    if ($serverResult.error) { $rows += ,@('Error', $serverResult.error) }
    
    Write-XY @{ table = @{ title="SMTP Check - $serverHost"; header=@('Property','Value'); rows=$rows; caption='' } }
    
    $results.Add([pscustomobject]$serverResult)
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  [pscustomobject]@{ tool='SMTP Checker'; serversChecked=$servers.Count; results=$results.ToArray() }
}

# ------------------------- Bandwidth/Speed Test -------------------------
function Invoke-BandwidthTest {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $mode = Get-Param $Params 'bwMode' 'cloudflare'
  $customUrl = Get-Param $Params 'bwCustomUrl' ''
  $testSize = Get-Param $Params 'bwTestSize' 'medium'
  
  Write-XYProgress 0.2 'Starting bandwidth test...'
  
  $result = @{ tool = 'Bandwidth Test'; mode = $mode; downloadSpeed = $null; uploadSpeed = $null; latency = $null }
  
  try {
    if ($mode -eq 'cloudflare') {
      # Test latency first
      Write-XYProgress 0.3 'Testing latency...'
      $latencies = @()
      for ($i = 0; $i -lt 3; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        Invoke-WebRequest -Uri 'https://cloudflare.com/cdn-cgi/trace' -UseBasicParsing -TimeoutSec 10 | Out-Null
        $sw.Stop()
        $latencies += $sw.ElapsedMilliseconds
      }
      $result.latency = [Math]::Round(($latencies | Measure-Object -Average).Average, 0)
      
      # Download test
      Write-XYProgress 0.4 'Testing download speed...'
      $sizes = @{ small = 1000000; medium = 10000000; large = 25000000 }
      $testBytes = $sizes[$testSize]
      $downloadUrl = "https://speed.cloudflare.com/__down?bytes=$testBytes"
      
      $sw = [System.Diagnostics.Stopwatch]::StartNew()
      $response = Invoke-WebRequest -Uri $downloadUrl -UseBasicParsing -TimeoutSec 120
      $sw.Stop()
      
      $downloadedBytes = $response.Content.Length
      $downloadSeconds = $sw.Elapsed.TotalSeconds
      $downloadMbps = [Math]::Round(($downloadedBytes * 8) / $downloadSeconds / 1000000, 2)
      $result.downloadSpeed = $downloadMbps
      $result.downloadBytes = $downloadedBytes
      $result.downloadTime = [Math]::Round($downloadSeconds, 2)
      
      # Upload test (smaller payload)
      Write-XYProgress 0.7 'Testing upload speed...'
      $uploadData = [byte[]]::new(1000000)  # 1MB
      [System.Random]::new().NextBytes($uploadData)
      
      $sw = [System.Diagnostics.Stopwatch]::StartNew()
      try {
        Invoke-WebRequest -Uri 'https://speed.cloudflare.com/__up' -Method POST -Body $uploadData -UseBasicParsing -TimeoutSec 60 | Out-Null
        $sw.Stop()
        $uploadSeconds = $sw.Elapsed.TotalSeconds
        $uploadMbps = [Math]::Round(($uploadData.Length * 8) / $uploadSeconds / 1000000, 2)
        $result.uploadSpeed = $uploadMbps
        $result.uploadTime = [Math]::Round($uploadSeconds, 2)
      } catch {
        $result.uploadSpeed = 'N/A'
        $result.uploadError = $_.Exception.Message
      }
    }
    elseif ($mode -eq 'custom' -and $customUrl) {
      Write-XYProgress 0.4 'Testing download from custom URL...'
      
      $sw = [System.Diagnostics.Stopwatch]::StartNew()
      $response = Invoke-WebRequest -Uri $customUrl -UseBasicParsing -TimeoutSec 120
      $sw.Stop()
      
      $downloadedBytes = $response.Content.Length
      $downloadSeconds = $sw.Elapsed.TotalSeconds
      $downloadMbps = [Math]::Round(($downloadedBytes * 8) / $downloadSeconds / 1000000, 2)
      
      $result.downloadSpeed = $downloadMbps
      $result.downloadBytes = $downloadedBytes
      $result.downloadTime = [Math]::Round($downloadSeconds, 2)
      $result.customUrl = $customUrl
    }
    else {
      throw 'Invalid mode or missing custom URL'
    }
    
    # Output table
    $rows = @(
      @('Mode', $(if ($mode -eq 'cloudflare') { 'Cloudflare Speed Test' } else { "Custom: $customUrl" })),
      @('Download Speed', "$($result.downloadSpeed) Mbps"),
      @('Download Size', "$([Math]::Round($result.downloadBytes / 1000000, 2)) MB"),
      @('Download Time', "$($result.downloadTime) seconds")
    )
    if ($result.uploadSpeed -and $result.uploadSpeed -ne 'N/A') {
      $rows += ,@('Upload Speed', "$($result.uploadSpeed) Mbps")
    }
    if ($result.latency) {
      $rows += ,@('Latency', "$($result.latency) ms")
    }
    
    Write-XY @{ table = @{ title='Bandwidth Test Results'; header=@('Metric','Value'); rows=$rows; caption='' } }
    
  } catch {
    $result.error = $_.Exception.Message
    Write-XY @{ table = @{ title='Bandwidth Test'; header=@('Error'); rows=@(,@($_.Exception.Message)); caption='Test failed' } }
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  [pscustomobject]$result
}

# ------------------------- TCP/UDP Listener -------------------------
function Invoke-PortListener {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $protocol = Get-Param $Params 'listenerProtocol' 'TCP'
  $port = [int](Get-Param $Params 'listenerPort' 8080)
  $timeout = [int](Get-Param $Params 'listenerTimeout' 60)
  $maxConnections = [int](Get-Param $Params 'listenerMaxConn' 10)
  
  if ($port -lt 1 -or $port -gt 65535) { throw "Invalid port: $port" }
  $timeout = [Math]::Min(300, [Math]::Max(5, $timeout))
  
  Write-XYProgress 0.2 "Starting $protocol listener on port $port for ${timeout}s..."
  
  $connections = [System.Collections.Generic.List[object]]::new()
  $startTime = [DateTime]::UtcNow
  
  try {
    if ($protocol -eq 'TCP') {
      $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $port)
      $listener.Start()
      
      Write-XY @{ table = @{ title='TCP Listener'; header=@('Status'); rows=@(,@("Listening on port $port...")); caption="Waiting for connections (max ${timeout}s)" } }
      
      $endTime = $startTime.AddSeconds($timeout)
      
      while ([DateTime]::UtcNow -lt $endTime -and $connections.Count -lt $maxConnections) {
        if ($listener.Pending()) {
          $client = $listener.AcceptTcpClient()
          $remoteEP = $client.Client.RemoteEndPoint
          $connTime = [DateTime]::UtcNow
          
          $dataReceived = ''
          try {
            $stream = $client.GetStream()
            $stream.ReadTimeout = 2000
            $buffer = [byte[]]::new(4096)
            # Wait up to 500ms for data to arrive
            $waitCount = 0
            while (-not $stream.DataAvailable -and $waitCount -lt 50) {
              Start-Sleep -Milliseconds 10
              $waitCount++
            }
            if ($stream.DataAvailable) {
              $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
              if ($bytesRead -gt 0) {
                $dataReceived = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
                if ($dataReceived.Length -gt 200) { $dataReceived = $dataReceived.Substring(0, 200) + '...' }
              }
            }
          } catch { }
          
          $connObj = [pscustomobject]@{
            timestamp = $connTime.ToString('HH:mm:ss')
            sourceIP = $remoteEP.Address.ToString()
            sourcePort = $remoteEP.Port
            data = $dataReceived
          }
          $connections.Add($connObj)
          
          # Output immediately and flush
          Write-XY @{ table = @{ title="TCP Connection #$($connections.Count)"; header=@('Property','Value'); rows=@(@('Time', $connObj.timestamp), @('Source', "$($connObj.sourceIP):$($connObj.sourcePort)"), @('Data', $(if ($connObj.data) { $connObj.data } else { '(no data)' }))); caption='' } }
          [Console]::Out.Flush()
          
          $client.Close()
        }
        Start-Sleep -Milliseconds 100
        
        $elapsed = ([DateTime]::UtcNow - $startTime).TotalSeconds
        Write-XYProgress (0.2 + (0.7 * $elapsed / $timeout)) "Listening... ($($connections.Count) connections)"
      }
      
      $listener.Stop()
    }
    else {
      # UDP Listener
      $udpClient = [System.Net.Sockets.UdpClient]::new($port)
      $udpClient.Client.ReceiveTimeout = 1000
      
      Write-XY @{ table = @{ title='UDP Listener'; header=@('Status'); rows=@(,@("Listening on port $port...")); caption="Waiting for datagrams (max ${timeout}s)" } }
      
      $endTime = $startTime.AddSeconds($timeout)
      
      while ([DateTime]::UtcNow -lt $endTime -and $connections.Count -lt $maxConnections) {
        try {
          $remoteEP = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
          $data = $udpClient.Receive([ref]$remoteEP)
          $connTime = [DateTime]::UtcNow
          
          $dataStr = [System.Text.Encoding]::UTF8.GetString($data)
          if ($dataStr.Length -gt 200) { $dataStr = $dataStr.Substring(0, 200) + '...' }
          
          $connObj = [pscustomobject]@{
            timestamp = $connTime.ToString('HH:mm:ss')
            sourceIP = $remoteEP.Address.ToString()
            sourcePort = $remoteEP.Port
            data = $dataStr
            size = $data.Length
          }
          $connections.Add($connObj)
          
          # Output immediately and flush
          Write-XY @{ table = @{ title="UDP Datagram #$($connections.Count)"; header=@('Property','Value'); rows=@(@('Time', $connObj.timestamp), @('Source', "$($connObj.sourceIP):$($connObj.sourcePort)"), @('Size', "$($connObj.size) bytes"), @('Data', $(if ($connObj.data) { $connObj.data } else { '(no data)' }))); caption='' } }
          [Console]::Out.Flush()
        } catch [System.Net.Sockets.SocketException] {
          # Timeout, continue
        }
        
        $elapsed = ([DateTime]::UtcNow - $startTime).TotalSeconds
        Write-XYProgress (0.2 + (0.7 * $elapsed / $timeout)) "Listening... ($($connections.Count) datagrams)"
      }
      
      $udpClient.Close()
    }
    
    # Output results
    if ($connections.Count -gt 0) {
      $rows = @()
      foreach ($c in $connections) {
        $dataPreview = if ($c.data) { $c.data.Substring(0, [Math]::Min(50, $c.data.Length)) } else { '-' }
        $rows += ,@($c.timestamp, "$($c.sourceIP):$($c.sourcePort)", $dataPreview)
      }
      Write-XY @{ table = @{ title="$protocol Connections Received"; header=@('Time','Source','Data Preview'); rows=$rows; caption="$($connections.Count) connection(s) received" } }
    } else {
      Write-XY @{ table = @{ title="$protocol Listener"; header=@('Result'); rows=@(,@('No connections received')); caption="Listened for $timeout seconds" } }
    }
    
  } catch {
    throw "Listener error: $($_.Exception.Message)"
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  [pscustomobject]@{ tool='Port Listener'; protocol=$protocol; port=$port; duration=$timeout; connectionsReceived=$connections.Count; connections=$connections.ToArray() }
}

# ------------------------- WebSocket Tester -------------------------
function Invoke-WebSocketTest {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $wsUrl = Get-Param $Params 'wsUrl' ''
  if (-not $wsUrl) { throw 'No WebSocket URL specified' }
  
  $sendMessage = Get-Param $Params 'wsSendMessage' ''
  $timeout = [int](Get-Param $Params 'wsTimeout' 10)
  
  Write-XYProgress 0.2 "Connecting to $wsUrl..."
  
  $result = @{ tool = 'WebSocket Tester'; url = $wsUrl; connected = $false; messagesSent = 0; messagesReceived = 0; messages = @() }
  
  try {
    $ws = [System.Net.WebSockets.ClientWebSocket]::new()
    $cts = [System.Threading.CancellationTokenSource]::new()
    $cts.CancelAfter([TimeSpan]::FromSeconds($timeout))
    
    $connectTask = $ws.ConnectAsync([Uri]$wsUrl, $cts.Token)
    $connectTask.Wait()
    
    $result.connected = $ws.State -eq 'Open'
    
    if ($result.connected) {
      Write-XYProgress 0.4 'Connected! Sending message...'
      
      # Send message if provided
      if ($sendMessage) {
        $sendBuffer = [System.Text.Encoding]::UTF8.GetBytes($sendMessage)
        $sendSegment = [System.ArraySegment[byte]]::new($sendBuffer)
        $sendTask = $ws.SendAsync($sendSegment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $cts.Token)
        $sendTask.Wait()
        $result.messagesSent++
        $result.messages += [pscustomobject]@{ direction = 'Sent'; data = $sendMessage; timestamp = [DateTime]::UtcNow.ToString('HH:mm:ss.fff') }
      }
      
      # Try to receive response
      Write-XYProgress 0.6 'Waiting for response...'
      $receiveBuffer = [byte[]]::new(8192)
      $receiveSegment = [System.ArraySegment[byte]]::new($receiveBuffer)
      
      try {
        $receiveCts = [System.Threading.CancellationTokenSource]::new()
        $receiveCts.CancelAfter([TimeSpan]::FromSeconds(5))
        $receiveTask = $ws.ReceiveAsync($receiveSegment, $receiveCts.Token)
        $receiveTask.Wait()
        
        if ($receiveTask.Result.Count -gt 0) {
          $receivedData = [System.Text.Encoding]::UTF8.GetString($receiveBuffer, 0, $receiveTask.Result.Count)
          $result.messagesReceived++
          $result.messages += [pscustomobject]@{ direction = 'Received'; data = $receivedData; timestamp = [DateTime]::UtcNow.ToString('HH:mm:ss.fff') }
        }
      } catch { }
      
      # Close connection
      if ($ws.State -eq 'Open') {
        $closeCts = [System.Threading.CancellationTokenSource]::new()
        $closeCts.CancelAfter([TimeSpan]::FromSeconds(5))
        $closeTask = $ws.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, 'Test complete', $closeCts.Token)
        $closeTask.Wait()
      }
    }
    
    # Output table
    $rows = @(
      @('URL', $wsUrl),
      @('Connected', $(if ($result.connected) { 'Yes' } else { 'No' })),
      @('Messages Sent', $result.messagesSent),
      @('Messages Received', $result.messagesReceived)
    )
    Write-XY @{ table = @{ title='WebSocket Test'; header=@('Property','Value'); rows=$rows; caption='' } }
    
    if ($result.messages.Count -gt 0) {
      $msgRows = @()
      foreach ($m in $result.messages) {
        $preview = if ($m.data.Length -gt 100) { $m.data.Substring(0, 100) + '...' } else { $m.data }
        $msgRows += ,@($m.timestamp, $m.direction, $preview)
      }
      Write-XY @{ table = @{ title='Messages'; header=@('Time','Direction','Data'); rows=$msgRows; caption='' } }
    }
    
  } catch {
    $result.error = $_.Exception.InnerException?.Message ?? $_.Exception.Message
    Write-XY @{ table = @{ title='WebSocket Test'; header=@('Property','Value'); rows=@(@('URL', $wsUrl), @('Error', $result.error)); caption='Connection failed' } }
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  [pscustomobject]$result
}

# ------------------------- API Health Monitor -------------------------
function Invoke-ApiHealthMonitor {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'apiSource' 'field'
  $endpointsInput = $null
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'apiDataPath' ''
    $endpointsInput = Get-NestedValue $inputData $path
    if ($null -eq $endpointsInput) { throw "Data path '$path' not found in input data" }
  } else { $endpointsInput = Get-Param $Params 'apiEndpoints' '' }
  
  $endpoints = @(Get-MultipleInputs $endpointsInput 20)
  if ($endpoints.Count -eq 0) { throw 'No endpoint(s) specified' }
  
  $expectedStatus = Get-Param $Params 'apiExpectedStatus' '200'
  $timeout = [int](Get-Param $Params 'apiTimeout' 10)
  $validateJson = Get-Param $Params 'apiValidateJson' ''
  
  Write-XYProgress 0.2 "Checking $($endpoints.Count) endpoint(s)..."
  
  $results = [System.Collections.Generic.List[object]]::new()
  $healthyCount = 0
  
  $epIndex = 0
  foreach ($endpoint in $endpoints) {
    $epIndex++
    if ($endpoint -notmatch '^https?://') { $endpoint = "https://$endpoint" }
    
    Write-XYProgress (0.2 + (0.7 * $epIndex / $endpoints.Count)) "Checking $endpoint..."
    
    $epResult = @{ endpoint = $endpoint; healthy = $false; statusCode = 0; responseTime = 0; error = ''; validationError = '' }
    
    try {
      $sw = [System.Diagnostics.Stopwatch]::StartNew()
      $response = Invoke-WebRequest -Uri $endpoint -UseBasicParsing -TimeoutSec $timeout -ErrorAction Stop
      $sw.Stop()
      
      $epResult.statusCode = $response.StatusCode
      $epResult.responseTime = $sw.ElapsedMilliseconds
      
      # Check expected status
      $expectedCodes = @($expectedStatus -split '[,;]' | ForEach-Object { [int]$_.Trim() })
      $statusMatch = $expectedCodes -contains $response.StatusCode
      
      # Validate JSON if specified
      $jsonValid = $true
      if ($validateJson -and $statusMatch) {
        try {
          $json = $response.Content | ConvertFrom-Json
          # Simple JSONPath-like validation: field=value or just field (exists check)
          foreach ($check in ($validateJson -split ';')) {
            $check = $check.Trim()
            if ($check -match '^([^=]+)=(.+)$') {
              $field = $Matches[1].Trim()
              $expected = $Matches[2].Trim()
              $actual = $json.PSObject.Properties[$field]?.Value
              if ([string]$actual -ne $expected) { $jsonValid = $false; $epResult.validationError = "$field expected '$expected', got '$actual'" }
            } elseif ($check) {
              if (-not $json.PSObject.Properties[$check]) { $jsonValid = $false; $epResult.validationError = "Field '$check' not found" }
            }
          }
        } catch {
          $jsonValid = $false
          $epResult.validationError = 'Invalid JSON response'
        }
      }
      
      $epResult.healthy = $statusMatch -and $jsonValid
      if ($epResult.healthy) { $healthyCount++ }
      
    } catch {
      $epResult.error = $_.Exception.Message
      if ($_.Exception.Response) {
        $epResult.statusCode = [int]$_.Exception.Response.StatusCode
      }
    }
    
    $results.Add([pscustomobject]$epResult)
  }
  
  # Output table
  $rows = @()
  foreach ($r in $results) {
    $status = if ($r.healthy) { 'Healthy' } elseif ($r.error) { 'Error' } else { 'Unhealthy' }
    $detail = if ($r.error) { $r.error.Substring(0, [Math]::Min(40, $r.error.Length)) } elseif ($r.validationError) { $r.validationError } else { "$($r.statusCode) - $($r.responseTime)ms" }
    $rows += ,@($r.endpoint, $status, $detail)
  }
  Write-XY @{ table = @{ title='API Health Monitor'; header=@('Endpoint','Status','Details'); rows=$rows; caption="$healthyCount/$($endpoints.Count) endpoints healthy" } }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  [pscustomobject]@{ tool='API Health Monitor'; endpointsChecked=$endpoints.Count; healthy=$healthyCount; unhealthy=($endpoints.Count - $healthyCount); results=$results.ToArray() }
}

# ------------------------- SNMP Query -------------------------
function Invoke-SnmpQuery {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'snmpSource' 'field'
  $hostsInput = $null
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'snmpDataPath' ''
    $hostsInput = Get-NestedValue $inputData $path
    if ($null -eq $hostsInput) { throw "Data path '$path' not found in input data" }
  } else { $hostsInput = Get-Param $Params 'snmpHosts' '' }
  
  $hosts = @(Get-MultipleInputs $hostsInput 10)
  if ($hosts.Count -eq 0) { throw 'No host(s) specified' }
  
  $version = Get-Param $Params 'snmpVersion' 'v2c'
  $community = Get-Param $Params 'snmpCommunity' 'public'
  $port = [int](Get-Param $Params 'snmpPort' 161)
  $timeout = [int](Get-Param $Params 'snmpTimeout' 5000)
  $customOids = Get-Param $Params 'snmpCustomOids' ''
  
  # SNMPv3 params
  $v3User = Get-Param $Params 'snmpV3User' ''
  $v3AuthProto = Get-Param $Params 'snmpV3AuthProto' 'SHA'
  $v3AuthPass = Get-Param $Params 'snmpV3AuthPass' ''
  $v3PrivProto = Get-Param $Params 'snmpV3PrivProto' 'AES'
  $v3PrivPass = Get-Param $Params 'snmpV3PrivPass' ''
  
  # Standard OIDs
  $standardOids = @{
    'sysDescr' = '1.3.6.1.2.1.1.1.0'
    'sysObjectID' = '1.3.6.1.2.1.1.2.0'
    'sysUpTime' = '1.3.6.1.2.1.1.3.0'
    'sysContact' = '1.3.6.1.2.1.1.4.0'
    'sysName' = '1.3.6.1.2.1.1.5.0'
    'sysLocation' = '1.3.6.1.2.1.1.6.0'
  }
  
  # Add custom OIDs
  if ($customOids) {
    foreach ($oid in ($customOids -split '[,;\n]+')) {
      $oid = $oid.Trim()
      if ($oid -match '^([^=]+)=(.+)$') {
        $standardOids[$Matches[1].Trim()] = $Matches[2].Trim()
      } elseif ($oid -match '^[0-9.]+$') {
        $standardOids["Custom_$oid"] = $oid
      }
    }
  }
  
  Write-XYProgress 0.2 "Querying $($hosts.Count) host(s) via SNMP $version..."
  
  $results = [System.Collections.Generic.List[object]]::new()
  
  # Note: Full SNMP implementation requires external library
  # This is a simplified UDP-based SNMPv1/v2c GET implementation
  
  foreach ($hostEntry in $hosts) {
    $hostAddr = $hostEntry -replace ':.*$', ''
    $hostPort = if ($hostEntry -match ':(\d+)$') { [int]$Matches[1] } else { $port }
    
    Write-XYProgress 0.4 "Querying $hostAddr..."
    
    $hostResult = @{ host = $hostAddr; port = $hostPort; version = $version; success = $false; values = @{}; error = '' }
    
    try {
      $udpClient = [System.Net.Sockets.UdpClient]::new()
      $udpClient.Client.ReceiveTimeout = $timeout
      $udpClient.Connect($hostAddr, $hostPort)
      
      foreach ($oidName in $standardOids.Keys) {
        $oid = $standardOids[$oidName]
        
        # Build simple SNMP GET request (v1/v2c)
        $oidParts = $oid -split '\.' | ForEach-Object { [int]$_ }
        $oidBytes = @()
        
        # Encode OID
        $oidBytes += (40 * $oidParts[0] + $oidParts[1])
        for ($i = 2; $i -lt $oidParts.Count; $i++) {
          $val = $oidParts[$i]
          if ($val -lt 128) {
            $oidBytes += $val
          } else {
            $encoded = @()
            while ($val -gt 0) {
              $encoded = ,($val -band 0x7F) + $encoded
              $val = $val -shr 7
            }
            for ($j = 0; $j -lt $encoded.Count - 1; $j++) { $encoded[$j] = $encoded[$j] -bor 0x80 }
            $oidBytes += $encoded
          }
        }
        
        $communityBytes = [System.Text.Encoding]::ASCII.GetBytes($community)
        
        # Build PDU
        $varbind = @(0x30, ($oidBytes.Count + 4), 0x06, $oidBytes.Count) + $oidBytes + @(0x05, 0x00)  # OID + NULL
        $varbindList = @(0x30, $varbind.Count) + $varbind
        
        $pduType = if ($version -eq 'v1') { 0xA0 } else { 0xA0 }  # GetRequest
        $requestId = @(0x02, 0x01, 0x01)  # Integer: 1
        $errorStatus = @(0x02, 0x01, 0x00)
        $errorIndex = @(0x02, 0x01, 0x00)
        $pduContent = $requestId + $errorStatus + $errorIndex + $varbindList
        $pdu = @($pduType, $pduContent.Count) + $pduContent
        
        $snmpVersion = if ($version -eq 'v1') { @(0x02, 0x01, 0x00) } else { @(0x02, 0x01, 0x01) }
        $communityField = @(0x04, $communityBytes.Count) + $communityBytes
        $message = $snmpVersion + $communityField + $pdu
        $packet = @(0x30, $message.Count) + $message
        
        $udpClient.Send([byte[]]$packet, $packet.Count) | Out-Null
        
        try {
          $remoteEP = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
          $response = $udpClient.Receive([ref]$remoteEP)
          
          # Simple response parsing - look for string/integer values
          $responseStr = [System.Text.Encoding]::ASCII.GetString($response)
          
          # Extract value (simplified - looks for printable ASCII after the OID)
          $valueStart = $response.Length - 1
          while ($valueStart -gt 0 -and $response[$valueStart] -ge 32 -and $response[$valueStart] -le 126) { $valueStart-- }
          $valueStart++
          
          if ($valueStart -lt $response.Length) {
            $value = [System.Text.Encoding]::ASCII.GetString($response, $valueStart, $response.Length - $valueStart).Trim()
            if ($value) { $hostResult.values[$oidName] = $value }
          }
          
          $hostResult.success = $true
        } catch { }
      }
      
      $udpClient.Close()
      
    } catch {
      $hostResult.error = $_.Exception.Message
    }
    
    # Output table
    if ($hostResult.success -and $hostResult.values.Count -gt 0) {
      $rows = @()
      foreach ($key in $hostResult.values.Keys) {
        $rows += ,@($key, $hostResult.values[$key])
      }
      Write-XY @{ table = @{ title="SNMP - $hostAddr"; header=@('OID Name','Value'); rows=$rows; caption="$($hostResult.values.Count) values retrieved" } }
    } else {
      $errMsg = if ($hostResult.error) { $hostResult.error } else { 'No response or empty values' }
      Write-XY @{ table = @{ title="SNMP - $hostAddr"; header=@('Status'); rows=@(,@($errMsg)); caption='Query failed' } }
    }
    
    $results.Add([pscustomobject]$hostResult)
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  [pscustomobject]@{ tool='SNMP Query'; hostsQueried=$hosts.Count; version=$version; results=$results.ToArray() }
}

# ------------------------- LDAP/AD Test -------------------------
function Invoke-LdapTest {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'ldapSource' 'field'
  $serversInput = $null
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'ldapDataPath' ''
    $serversInput = Get-NestedValue $inputData $path
    if ($null -eq $serversInput) { throw "Data path '$path' not found in input data" }
  } else { $serversInput = Get-Param $Params 'ldapServers' '' }
  
  $servers = @(Get-MultipleInputs $serversInput 10)
  if ($servers.Count -eq 0) { throw 'No LDAP server(s) specified' }
  
  $port = [int](Get-Param $Params 'ldapPort' 389)
  $useSsl = [bool](Get-Param $Params 'ldapUseSsl' $false)
  $baseDn = Get-Param $Params 'ldapBaseDn' ''
  $bindDn = Get-Param $Params 'ldapBindDn' ''
  $bindPassword = Get-Param $Params 'ldapBindPassword' ''
  $searchFilter = Get-Param $Params 'ldapSearchFilter' '(objectClass=*)'
  $searchScope = Get-Param $Params 'ldapSearchScope' 'base'
  
  if ($useSsl -and $port -eq 389) { $port = 636 }
  
  Write-XYProgress 0.2 "Testing $($servers.Count) LDAP server(s)..."
  
  $results = [System.Collections.Generic.List[object]]::new()
  
  foreach ($server in $servers) {
    $serverHost = $server -replace ':.*$', ''
    $serverPort = if ($server -match ':(\d+)$') { [int]$Matches[1] } else { $port }
    
    Write-XYProgress 0.4 "Testing $serverHost`:$serverPort..."
    
    $serverResult = @{
      server = $serverHost; port = $serverPort; ssl = $useSsl
      connected = $false; bound = $false; searchSuccess = $false
      bindType = 'Anonymous'; searchResults = 0; error = ''
    }
    
    try {
      # Use System.DirectoryServices.Protocols for LDAP
      $ldapId = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($serverHost, $serverPort)
      $ldapConn = [System.DirectoryServices.Protocols.LdapConnection]::new($ldapId)
      
      $ldapConn.SessionOptions.ProtocolVersion = 3
      $ldapConn.SessionOptions.SecureSocketLayer = $useSsl
      $ldapConn.Timeout = [TimeSpan]::FromSeconds(10)
      
      # Try to bind
      if ($bindDn -and $bindPassword) {
        $cred = [System.Net.NetworkCredential]::new($bindDn, $bindPassword)
        $ldapConn.Credential = $cred
        $ldapConn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
        $serverResult.bindType = 'Authenticated'
      } else {
        $ldapConn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
      }
      
      $ldapConn.Bind()
      $serverResult.connected = $true
      $serverResult.bound = $true
      
      # Try search if baseDn provided
      if ($baseDn) {
        $scope = switch ($searchScope) {
          'base' { [System.DirectoryServices.Protocols.SearchScope]::Base }
          'one' { [System.DirectoryServices.Protocols.SearchScope]::OneLevel }
          'sub' { [System.DirectoryServices.Protocols.SearchScope]::Subtree }
          default { [System.DirectoryServices.Protocols.SearchScope]::Base }
        }
        
        $searchReq = [System.DirectoryServices.Protocols.SearchRequest]::new($baseDn, $searchFilter, $scope, $null)
        $searchReq.SizeLimit = 10
        
        $searchResp = $ldapConn.SendRequest($searchReq)
        $serverResult.searchSuccess = $true
        $serverResult.searchResults = $searchResp.Entries.Count
      }
      
      $ldapConn.Dispose()
      
    } catch {
      $serverResult.error = $_.Exception.InnerException?.Message ?? $_.Exception.Message
    }
    
    # Output table
    $rows = @(
      @('Server', "$serverHost`:$serverPort"),
      @('SSL/TLS', $(if ($useSsl) { 'Yes' } else { 'No' })),
      @('Connected', $(if ($serverResult.connected) { 'Yes' } else { 'No' })),
      @('Bind Type', $serverResult.bindType),
      @('Bind Success', $(if ($serverResult.bound) { 'Yes' } else { 'No' }))
    )
    if ($baseDn) {
      $rows += ,@('Search Base', $baseDn)
      $rows += ,@('Search Success', $(if ($serverResult.searchSuccess) { 'Yes' } else { 'No' }))
      $rows += ,@('Results Found', $serverResult.searchResults)
    }
    if ($serverResult.error) { $rows += ,@('Error', $serverResult.error) }
    
    $caption = if ($serverResult.bound) { 'Connection successful' } else { 'Connection failed' }
    Write-XY @{ table = @{ title="LDAP Test - $serverHost"; header=@('Property','Value'); rows=$rows; caption=$caption } }
    
    $results.Add([pscustomobject]$serverResult)
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  [pscustomobject]@{ tool='LDAP Test'; serversTested=$servers.Count; results=$results.ToArray() }
}

# ------------------------- Main -------------------------
try {
  $job = Read-JobFromStdin
  $params = $job.params
  $tool = if ($params.PSObject.Properties.Name -contains 'tool') { $params.tool } else { 'pingTest' }
  $cwd = if ($job.PSObject.Properties.Name -contains 'cwd') { [string]$job.cwd } else { (Get-Location).Path }
  $jobInput = if ($job.PSObject.Properties.Name -contains 'input') { $job.input } else { @{} }

  $result = $null
  switch ($tool) {
    'ipAddressTools'   { $result = Invoke-IPAddressTools -Params $params -JobInput $jobInput }
    'jwtDecoder'       { $result = Invoke-JWTDecoder -Params $params -JobInput $jobInput }
    'pingTest'         { $result = Invoke-PingTest -Params $params -JobInput $jobInput }
    'dnsLookup'        { $result = Invoke-DnsLookup -Params $params -JobInput $jobInput }
    'traceroute'       { $result = Invoke-Traceroute -Params $params -JobInput $jobInput }
    'portScanner'      { $result = Invoke-PortScanner -Params $params -JobInput $jobInput }
    'httpChecker'      { $result = Invoke-HttpChecker -Params $params -JobInput $jobInput }
    'sslChecker'       { $result = Invoke-SslChecker -Params $params -JobInput $jobInput }
    'whoisLookup'      { $result = Invoke-WhoisLookup -Params $params -JobInput $jobInput }
    'ntpCheck'         { $result = Invoke-NtpCheck -Params $params -JobInput $jobInput }
    'networkScanner'   { $result = Invoke-NetworkScanner -Params $params -JobInput $jobInput }
    'wakeOnLan'        { $result = Invoke-WakeOnLan -Params $params -JobInput $jobInput }
    'subnetCalculator' { $result = Invoke-SubnetCalculator -Params $params -JobInput $jobInput }
    'ipGeolocation'    { $result = Invoke-IPGeolocation -Params $params -JobInput $jobInput }
    'emailAuthChecker' { $result = Invoke-EmailAuthChecker -Params $params -JobInput $jobInput }
    'blacklistChecker' { $result = Invoke-BlacklistChecker -Params $params -JobInput $jobInput }
    'smtpChecker'      { $result = Invoke-SmtpChecker -Params $params -JobInput $jobInput }
    'bandwidthTest'    { $result = Invoke-BandwidthTest -Params $params -JobInput $jobInput }
    'portListener'     { $result = Invoke-PortListener -Params $params -JobInput $jobInput }
    'websocketTester'  { $result = Invoke-WebSocketTest -Params $params -JobInput $jobInput }
    'apiHealthMonitor' { $result = Invoke-ApiHealthMonitor -Params $params -JobInput $jobInput }
    'snmpQuery'        { $result = Invoke-SnmpQuery -Params $params -JobInput $jobInput }
    'ldapTest'         { $result = Invoke-LdapTest -Params $params -JobInput $jobInput }
    default            { throw "Unknown tool: $tool" }
  }

  Write-XYSuccess -Data $result -Description ("{0} completed successfully" -f $result.tool)
  [Console]::Out.Flush()
  exit 0
}
catch {
  Write-XYError -Code 1 -Description ($_.Exception.Message)
  [Console]::Out.Flush()
  exit 1
}
