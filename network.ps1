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
  
  # Extract common claims
  $alg = $header.alg ?? 'N/A'
  $typ = $header.typ ?? 'N/A'
  $iss = $payload.iss ?? 'N/A'
  $sub = $payload.sub ?? 'N/A'
  $aud = if ($payload.aud) { if ($payload.aud -is [array]) { $payload.aud -join ', ' } else { $payload.aud } } else { 'N/A' }
  $exp = 'N/A'; $expDate = 'N/A'
  if ($payload.exp) {
    $exp = $payload.exp
    $expDate = [DateTimeOffset]::FromUnixTimeSeconds($payload.exp).DateTime.ToString('yyyy-MM-dd HH:mm:ss UTC')
  }
  $iat = 'N/A'; $iatDate = 'N/A'
  if ($payload.iat) {
    $iat = $payload.iat
    $iatDate = [DateTimeOffset]::FromUnixTimeSeconds($payload.iat).DateTime.ToString('yyyy-MM-dd HH:mm:ss UTC')
  }
  
  $isExpired = $false
  if ($payload.exp) { $isExpired = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -gt $payload.exp }
  
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
  $host_ = ''
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'pingDataPath' ''
    $val = Get-NestedValue $inputData $path
    if ($null -eq $val) { throw "Data path '$path' not found in input data" }
    $host_ = [string]$val
  } else { $host_ = Get-Param $Params 'pingHost' '' }
  
  if (-not $host_) { throw 'No host specified' }
  
  $count = [Math]::Min(10, [Math]::Max(1, [int](Get-Param $Params 'pingCount' 4)))
  $timeout = [Math]::Min(30000, [Math]::Max(100, [int](Get-Param $Params 'pingTimeout' 1000)))
  
  Write-XYProgress 0.2 "Pinging $host_..."
  
  $pinger = [System.Net.NetworkInformation.Ping]::new()
  $results = [System.Collections.Generic.List[object]]::new()
  $successful = 0
  $failed = 0
  $latencies = [System.Collections.Generic.List[long]]::new()
  
  for ($i = 1; $i -le $count; $i++) {
    Write-XYProgress (0.2 + (0.6 * $i / $count)) "Ping $i of $count..."
    try {
      $reply = $pinger.Send($host_, $timeout)
      if ($reply.Status -eq 'Success') {
        $successful++
        $latencies.Add($reply.RoundtripTime)
        $results.Add([pscustomobject]@{ seq=$i; status='Success'; time="$($reply.RoundtripTime)ms"; ttl=$reply.Options.Ttl; address=$reply.Address.ToString() })
      } else {
        $failed++
        $results.Add([pscustomobject]@{ seq=$i; status=$reply.Status.ToString(); time='-'; ttl='-'; address='-' })
      }
    } catch {
      $failed++
      $results.Add([pscustomobject]@{ seq=$i; status='Error'; time='-'; ttl='-'; address='-' })
    }
    if ($i -lt $count) { Start-Sleep -Milliseconds 100 }
  }
  $pinger.Dispose()
  
  Write-XYProgress 0.9 'Calculating statistics...'
  
  $minLatency = if ($latencies.Count -gt 0) { ($latencies | Measure-Object -Minimum).Minimum } else { 0 }
  $maxLatency = if ($latencies.Count -gt 0) { ($latencies | Measure-Object -Maximum).Maximum } else { 0 }
  $avgLatency = if ($latencies.Count -gt 0) { [Math]::Round(($latencies | Measure-Object -Average).Average, 2) } else { 0 }
  $lossPercent = [Math]::Round(($failed / $count) * 100, 1)
  
  # Resolve hostname
  $resolvedIP = ''
  try { $resolvedIP = ([System.Net.Dns]::GetHostAddresses($host_) | Select-Object -First 1).ToString() } catch { }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  $rows = $results | ForEach-Object { @($_.seq, $_.status, $_.time, $_.ttl, $_.address) }
  Write-XY @{ table = @{ title="Ping Results - $host_"; header=@('Seq','Status','Time','TTL','Address'); rows=$rows; caption="$successful/$count successful, $lossPercent% loss" } }
  
  $statsRows = @(
    @('Host', $host_),
    @('Resolved IP', $(if ($resolvedIP) { $resolvedIP } else { 'N/A' })),
    @('Packets Sent', $count),
    @('Packets Received', $successful),
    @('Packets Lost', $failed),
    @('Loss Percentage', "$lossPercent%"),
    @('Min Latency', "${minLatency}ms"),
    @('Max Latency', "${maxLatency}ms"),
    @('Avg Latency', "${avgLatency}ms")
  )
  Write-XY @{ table = @{ title='Statistics'; header=@('Metric','Value'); rows=$statsRows; caption='' } }
  
  [pscustomobject]@{ tool='Ping Test'; host=$host_; resolvedIP=$resolvedIP; count=$count; successful=$successful; failed=$failed; lossPercent=$lossPercent; minLatency=$minLatency; maxLatency=$maxLatency; avgLatency=$avgLatency; results=$results.ToArray() }
}

# ------------------------- DNS Lookup -------------------------
function Invoke-DnsLookup {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'dnsSource' 'field'
  $query = ''
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'dnsDataPath' ''
    $val = Get-NestedValue $inputData $path
    if ($null -eq $val) { throw "Data path '$path' not found in input data" }
    $query = [string]$val
  } else { $query = Get-Param $Params 'dnsQuery' '' }
  
  if (-not $query) { throw 'No query specified' }
  
  $recordType = Get-Param $Params 'dnsRecordType' 'A'
  $dnsServer = Get-Param $Params 'dnsServer' ''
  
  Write-XYProgress 0.3 "Resolving $recordType record for $query..."
  
  $results = [System.Collections.Generic.List[object]]::new()
  $success = $true
  $errorMsg = ''
  
  try {
    # Handle PTR (reverse DNS) specially
    if ($recordType -eq 'PTR') {
      # Convert IP to reverse lookup format
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
      # Use nslookup for other record types
      $nslookupArgs = if ($dnsServer) { "-type=$recordType $query $dnsServer" } else { "-type=$recordType $query" }
      $output = & nslookup $nslookupArgs.Split(' ') 2>&1
      $outputText = $output -join "`n"
      
      # Parse nslookup output
      switch ($recordType) {
        'MX' {
          $matches = [regex]::Matches($outputText, 'mail exchanger = (.+)')
          foreach ($m in $matches) {
            $parts = $m.Groups[1].Value.Trim() -split '\s+'
            $priority = if ($parts.Count -gt 1) { $parts[0] } else { '-' }
            $server = if ($parts.Count -gt 1) { $parts[-1] } else { $parts[0] }
            $results.Add([pscustomobject]@{ type='MX'; name=$query; value="$priority $server"; ttl='-' })
          }
        }
        'TXT' {
          $matches = [regex]::Matches($outputText, 'text\s*=\s*"([^"]+)"')
          foreach ($m in $matches) {
            $results.Add([pscustomobject]@{ type='TXT'; name=$query; value=$m.Groups[1].Value; ttl='-' })
          }
        }
        'NS' {
          $matches = [regex]::Matches($outputText, 'nameserver = (.+)')
          foreach ($m in $matches) {
            $results.Add([pscustomobject]@{ type='NS'; name=$query; value=$m.Groups[1].Value.Trim(); ttl='-' })
          }
        }
        'CNAME' {
          $matches = [regex]::Matches($outputText, 'canonical name = (.+)')
          foreach ($m in $matches) {
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
  } catch {
    $success = $false
    $errorMsg = $_.Exception.Message
    $results.Add([pscustomobject]@{ type=$recordType; name=$query; value="Error: $errorMsg"; ttl='-' })
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  $rows = $results | ForEach-Object { @($_.type, $_.name, $_.value, $_.ttl) }
  Write-XY @{ table = @{ title="DNS Lookup - $recordType"; header=@('Type','Name','Value','TTL'); rows=$rows; caption=$(if ($dnsServer) { "Using DNS server: $dnsServer" } else { 'Using system DNS' }) } }
  
  [pscustomobject]@{ tool='DNS Lookup'; query=$query; recordType=$recordType; dnsServer=$(if ($dnsServer) { $dnsServer } else { 'system' }); success=$success; results=$results.ToArray(); error=$errorMsg }
}

# ------------------------- Traceroute -------------------------
function Invoke-Traceroute {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'traceSource' 'field'
  $host_ = ''
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'traceDataPath' ''
    $val = Get-NestedValue $inputData $path
    if ($null -eq $val) { throw "Data path '$path' not found in input data" }
    $host_ = [string]$val
  } else { $host_ = Get-Param $Params 'traceHost' '' }
  
  if (-not $host_) { throw 'No host specified' }
  
  $maxHops = [Math]::Min(64, [Math]::Max(1, [int](Get-Param $Params 'traceMaxHops' 30)))
  $timeout = [Math]::Min(10000, [Math]::Max(100, [int](Get-Param $Params 'traceTimeout' 3000)))
  $resolveNames = if ($Params.PSObject.Properties.Name -contains 'traceResolveNames') { [bool]$Params.traceResolveNames } else { $true }
  
  Write-XYProgress 0.2 "Tracing route to $host_..."
  
  $pinger = [System.Net.NetworkInformation.Ping]::new()
  $options = [System.Net.NetworkInformation.PingOptions]::new()
  $buffer = [byte[]]::new(32)
  $results = [System.Collections.Generic.List[object]]::new()
  $reached = $false
  
  # Resolve destination first
  $destIP = ''
  try { $destIP = ([System.Net.Dns]::GetHostAddresses($host_) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).ToString() } catch { $destIP = $host_ }
  
  for ($ttl = 1; $ttl -le $maxHops; $ttl++) {
    Write-XYProgress (0.2 + (0.7 * $ttl / $maxHops)) "Hop $ttl..."
    $options.Ttl = $ttl
    
    $hopIP = '*'
    $hopName = '*'
    $hopTime = '*'
    
    try {
      $reply = $pinger.Send($host_, $timeout, $buffer, $options)
      if ($reply.Status -eq 'TtlExpired' -or $reply.Status -eq 'Success') {
        $hopIP = $reply.Address.ToString()
        $hopTime = "$($reply.RoundtripTime)ms"
        
        if ($resolveNames) {
          try {
            $hostEntry = [System.Net.Dns]::GetHostEntry($reply.Address)
            $hopName = $hostEntry.HostName
          } catch { $hopName = $hopIP }
        } else { $hopName = $hopIP }
        
        if ($reply.Status -eq 'Success') { $reached = $true }
      } elseif ($reply.Status -eq 'TimedOut') {
        $hopIP = '*'; $hopName = 'Request timed out'; $hopTime = '*'
      }
    } catch {
      $hopIP = '*'; $hopName = 'Error'; $hopTime = '*'
    }
    
    $results.Add([pscustomobject]@{ hop=$ttl; ip=$hopIP; hostname=$hopName; time=$hopTime })
    
    if ($reached) { break }
  }
  $pinger.Dispose()
  
  Write-XYProgress 0.95 'Finalizing...'
  
  $rows = $results | ForEach-Object { @($_.hop, $_.ip, $_.hostname, $_.time) }
  Write-XY @{ table = @{ title="Traceroute - $host_"; header=@('Hop','IP Address','Hostname','Time'); rows=$rows; caption=$(if ($reached) { "Destination reached in $($results.Count) hops" } else { "Destination not reached within $maxHops hops" }) } }
  
  [pscustomobject]@{ tool='Traceroute'; host=$host_; destinationIP=$destIP; maxHops=$maxHops; hopsUsed=$results.Count; reached=$reached; results=$results.ToArray() }
}

# ------------------------- Port Scanner -------------------------
function Invoke-PortScanner {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'portSource' 'field'
  $host_ = ''
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'portDataPath' ''
    $val = Get-NestedValue $inputData $path
    if ($null -eq $val) { throw "Data path '$path' not found in input data" }
    $host_ = [string]$val
  } else { $host_ = Get-Param $Params 'portHost' '' }
  
  if (-not $host_) { throw 'No host specified' }
  
  $portsInput = Get-Param $Params 'portPorts' '80,443'
  $timeout = [Math]::Min(30000, [Math]::Max(100, [int](Get-Param $Params 'portTimeout' 1000)))
  
  # Parse ports (supports comma-separated and ranges like 80-85)
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
  
  Write-XYProgress 0.2 "Scanning $($ports.Count) port(s) on $host_..."
  
  $results = [System.Collections.Generic.List[object]]::new()
  $openPorts = 0
  $closedPorts = 0
  
  $commonPorts = @{
    20='FTP Data'; 21='FTP'; 22='SSH'; 23='Telnet'; 25='SMTP'; 53='DNS'; 80='HTTP'; 110='POP3'
    143='IMAP'; 443='HTTPS'; 465='SMTPS'; 587='SMTP Submission'; 993='IMAPS'; 995='POP3S'
    3306='MySQL'; 3389='RDP'; 5432='PostgreSQL'; 6379='Redis'; 8080='HTTP Proxy'; 8443='HTTPS Alt'
  }
  
  $portIndex = 0
  foreach ($port in $ports) {
    $portIndex++
    Write-XYProgress (0.2 + (0.7 * $portIndex / $ports.Count)) "Scanning port $port..."
    
    $status = 'Closed'
    $service = if ($commonPorts.ContainsKey($port)) { $commonPorts[$port] } else { '-' }
    
    try {
      $client = [System.Net.Sockets.TcpClient]::new()
      $result = $client.BeginConnect($host_, $port, $null, $null)
      $success = $result.AsyncWaitHandle.WaitOne($timeout, $false)
      if ($success -and $client.Connected) {
        $status = 'Open'
        $openPorts++
      } else {
        $closedPorts++
      }
      $client.Close()
    } catch {
      $closedPorts++
    }
    
    $results.Add([pscustomobject]@{ port=$port; status=$status; service=$service })
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  $rows = $results | ForEach-Object { @($_.port, $_.status, $_.service) }
  Write-XY @{ table = @{ title="Port Scan - $host_"; header=@('Port','Status','Service'); rows=$rows; caption="$openPorts open, $closedPorts closed" } }
  
  [pscustomobject]@{ tool='Port Scanner'; host=$host_; portsScanned=$ports.Count; openPorts=$openPorts; closedPorts=$closedPorts; timeout=$timeout; results=$results.ToArray() }
}

# ------------------------- HTTP Status Checker -------------------------
function Invoke-HttpChecker {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'httpSource' 'field'
  $url = ''
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'httpDataPath' ''
    $val = Get-NestedValue $inputData $path
    if ($null -eq $val) { throw "Data path '$path' not found in input data" }
    $url = [string]$val
  } else { $url = Get-Param $Params 'httpUrl' '' }
  
  if (-not $url) { throw 'No URL specified' }
  if ($url -notmatch '^https?://') { $url = "https://$url" }
  
  $method = Get-Param $Params 'httpMethod' 'GET'
  $timeout = [Math]::Min(60, [Math]::Max(1, [int](Get-Param $Params 'httpTimeout' 10)))
  $followRedirects = if ($Params.PSObject.Properties.Name -contains 'httpFollowRedirects') { [bool]$Params.httpFollowRedirects } else { $true }
  
  Write-XYProgress 0.3 "Sending $method request to $url..."
  
  $statusCode = 0
  $statusDesc = ''
  $responseTime = 0
  $headers = @{}
  $contentType = ''
  $contentLength = 0
  $server = ''
  $redirectUrl = ''
  $errorMsg = ''
  $success = $true
  
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
  } catch {
    $success = $false
    $errorMsg = $_.Exception.InnerException?.Message ?? $_.Exception.Message
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  $summaryRows = @(
    @('URL', $url),
    @('Method', $method),
    @('Status Code', $(if ($success) { "$statusCode $statusDesc" } else { 'Error' })),
    @('Response Time', "${responseTime}ms"),
    @('Content-Type', $contentType),
    @('Content-Length', $(if ($contentLength -gt 0) { "$contentLength bytes" } else { '-' })),
    @('Server', $server)
  )
  if ($redirectUrl) { $summaryRows += ,@('Redirect URL', $redirectUrl) }
  if ($errorMsg) { $summaryRows += ,@('Error', $errorMsg) }
  
  Write-XY @{ table = @{ title='HTTP Response'; header=@('Property','Value'); rows=$summaryRows; caption=$(if ($success) { 'Request completed' } else { 'Request failed' }) } }
  
  if ($success -and $headers.Count -gt 0) {
    $headerRows = $headers.GetEnumerator() | Sort-Object Key | ForEach-Object {
      $val = if ($_.Value.Length -gt 60) { $_.Value.Substring(0, 60) + '...' } else { $_.Value }
      @($_.Key, $val)
    }
    Write-XY @{ table = @{ title='Response Headers'; header=@('Header','Value'); rows=$headerRows; caption='' } }
  }
  
  [pscustomobject]@{ tool='HTTP Status Checker'; url=$url; method=$method; success=$success; statusCode=$statusCode; statusDescription=$statusDesc; responseTime=$responseTime; contentType=$contentType; contentLength=$contentLength; server=$server; redirectUrl=$redirectUrl; headers=$headers; error=$errorMsg }
}

# ------------------------- SSL Certificate Checker -------------------------
function Invoke-SslChecker {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'sslSource' 'field'
  $host_ = ''
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'sslDataPath' ''
    $val = Get-NestedValue $inputData $path
    if ($null -eq $val) { throw "Data path '$path' not found in input data" }
    $host_ = [string]$val
  } else { $host_ = Get-Param $Params 'sslHost' '' }
  
  if (-not $host_) { throw 'No host specified' }
  
  # Remove protocol if present
  $host_ = $host_ -replace '^https?://', '' -replace '/.*$', ''
  $port = 443
  if ($host_ -match '^(.+):(\d+)$') { $host_ = $Matches[1]; $port = [int]$Matches[2] }
  
  Write-XYProgress 0.3 "Checking SSL certificate for $host_`:$port..."
  
  $cert = $null
  $chain = $null
  $success = $true
  $errorMsg = ''
  
  try {
    $client = [System.Net.Sockets.TcpClient]::new($host_, $port)
    $sslStream = [System.Net.Security.SslStream]::new($client.GetStream(), $false, { $true })
    $sslStream.AuthenticateAsClient($host_)
    
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($sslStream.RemoteCertificate)
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    $chain.Build($cert) | Out-Null
    
    $sslStream.Close()
    $client.Close()
  } catch {
    $success = $false
    $errorMsg = $_.Exception.InnerException?.Message ?? $_.Exception.Message
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  if ($success -and $cert) {
    $now = [DateTime]::UtcNow
    $notBefore = $cert.NotBefore.ToUniversalTime()
    $notAfter = $cert.NotAfter.ToUniversalTime()
    $daysUntilExpiry = [Math]::Floor(($notAfter - $now).TotalDays)
    $isExpired = $now -gt $notAfter
    $isNotYetValid = $now -lt $notBefore
    
    $subject = $cert.Subject
    $issuer = $cert.Issuer
    $thumbprint = $cert.Thumbprint
    $serialNumber = $cert.SerialNumber
    $signatureAlg = $cert.SignatureAlgorithm.FriendlyName
    
    # Extract CN from subject
    $cn = ''
    if ($subject -match 'CN=([^,]+)') { $cn = $Matches[1] }
    
    # Get SANs
    $sans = [System.Collections.Generic.List[string]]::new()
    foreach ($ext in $cert.Extensions) {
      if ($ext.Oid.Value -eq '2.5.29.17') {
        $sanText = $ext.Format($false)
        $sanMatches = [regex]::Matches($sanText, 'DNS Name=([^,\s]+)')
        foreach ($m in $sanMatches) { $sans.Add($m.Groups[1].Value) }
      }
    }
    
    $validity = if ($isExpired) { 'EXPIRED' } elseif ($isNotYetValid) { 'NOT YET VALID' } elseif ($daysUntilExpiry -le 30) { 'EXPIRING SOON' } else { 'Valid' }
    
    $summaryRows = @(
      @('Host', "$host_`:$port"),
      @('Common Name (CN)', $cn),
      @('Subject', $(if ($subject.Length -gt 60) { $subject.Substring(0,60) + '...' } else { $subject })),
      @('Issuer', $(if ($issuer.Length -gt 60) { $issuer.Substring(0,60) + '...' } else { $issuer })),
      @('Valid From', $notBefore.ToString('yyyy-MM-dd HH:mm:ss UTC')),
      @('Valid Until', $notAfter.ToString('yyyy-MM-dd HH:mm:ss UTC')),
      @('Days Until Expiry', $daysUntilExpiry),
      @('Status', $validity),
      @('Signature Algorithm', $signatureAlg),
      @('Thumbprint', $thumbprint),
      @('Serial Number', $serialNumber)
    )
    
    Write-XY @{ table = @{ title='SSL Certificate'; header=@('Property','Value'); rows=$summaryRows; caption=$validity } }
    
    if ($sans.Count -gt 0) {
      $sanRows = for ($i = 0; $i -lt [Math]::Min($sans.Count, 20); $i++) { ,@(($i + 1), $sans[$i]) }
      Write-XY @{ table = @{ title='Subject Alternative Names (SANs)'; header=@('#','DNS Name'); rows=$sanRows; caption="$($sans.Count) SAN(s)" } }
    }
    
    if ($chain -and $chain.ChainElements.Count -gt 1) {
      $chainRows = for ($i = 0; $i -lt $chain.ChainElements.Count; $i++) {
        $elem = $chain.ChainElements[$i].Certificate
        $elemCn = ''; if ($elem.Subject -match 'CN=([^,]+)') { $elemCn = $Matches[1] }
        @($i, $elemCn, $elem.NotAfter.ToString('yyyy-MM-dd'))
      }
      Write-XY @{ table = @{ title='Certificate Chain'; header=@('Level','Common Name','Expires'); rows=$chainRows; caption='' } }
    }
    
    [pscustomobject]@{ tool='SSL Certificate Checker'; host="$host_`:$port"; success=$true; commonName=$cn; subject=$subject; issuer=$issuer; validFrom=$notBefore; validUntil=$notAfter; daysUntilExpiry=$daysUntilExpiry; isExpired=$isExpired; validity=$validity; signatureAlgorithm=$signatureAlg; thumbprint=$thumbprint; serialNumber=$serialNumber; sans=$sans.ToArray() }
  } else {
    Write-XY @{ table = @{ title='SSL Certificate Error'; header=@('Property','Value'); rows=@(@('Host', "$host_`:$port"), @('Error', $errorMsg)); caption='Failed to retrieve certificate' } }
    [pscustomobject]@{ tool='SSL Certificate Checker'; host="$host_`:$port"; success=$false; error=$errorMsg }
  }
}

# ------------------------- WHOIS Lookup -------------------------
function Invoke-WhoisLookup {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = Get-Param $Params 'whoisSource' 'field'
  $domain = ''
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = Get-Param $Params 'whoisDataPath' ''
    $val = Get-NestedValue $inputData $path
    if ($null -eq $val) { throw "Data path '$path' not found in input data" }
    $domain = [string]$val
  } else { $domain = Get-Param $Params 'whoisDomain' '' }
  
  if (-not $domain) { throw 'No domain specified' }
  
  # Clean domain
  $domain = $domain -replace '^https?://', '' -replace '/.*$', '' -replace '^www\.', ''
  
  Write-XYProgress 0.3 "Looking up WHOIS for $domain..."
  
  $whoisData = @{}
  $rawResponse = ''
  $success = $true
  $errorMsg = ''
  
  try {
    # Determine WHOIS server based on TLD
    $tld = ($domain -split '\.')[-1].ToLower()
    $whoisServer = switch ($tld) {
      'com' { 'whois.verisign-grs.com' }
      'net' { 'whois.verisign-grs.com' }
      'org' { 'whois.pir.org' }
      'io' { 'whois.nic.io' }
      'co' { 'whois.nic.co' }
      'me' { 'whois.nic.me' }
      'info' { 'whois.afilias.net' }
      'biz' { 'whois.biz' }
      'dev' { 'whois.nic.google' }
      'app' { 'whois.nic.google' }
      'uk' { 'whois.nic.uk' }
      'de' { 'whois.denic.de' }
      'fr' { 'whois.nic.fr' }
      'nl' { 'whois.domain-registry.nl' }
      'eu' { 'whois.eu' }
      'au' { 'whois.auda.org.au' }
      default { 'whois.iana.org' }
    }
    
    $client = [System.Net.Sockets.TcpClient]::new($whoisServer, 43)
    $stream = $client.GetStream()
    $writer = [System.IO.StreamWriter]::new($stream)
    $reader = [System.IO.StreamReader]::new($stream)
    
    $writer.WriteLine($domain)
    $writer.Flush()
    
    $rawResponse = $reader.ReadToEnd()
    
    $reader.Close()
    $writer.Close()
    $client.Close()
    
    # Parse common WHOIS fields
    $patterns = @{
      'Registrar' = 'Registrar:\s*(.+)'
      'Creation Date' = '(Creation Date|Created|Registered):\s*(.+)'
      'Expiration Date' = '(Expir[ey]|Registry Expiry Date).*?:\s*(.+)'
      'Updated Date' = '(Updated Date|Last Updated|Modified):\s*(.+)'
      'Name Servers' = 'Name Server:\s*(.+)'
      'Status' = '(Domain )?Status:\s*(.+)'
      'Registrant' = 'Registrant.*?:\s*(.+)'
      'Admin Contact' = 'Admin.*?(Name|Contact):\s*(.+)'
    }
    
    foreach ($key in $patterns.Keys) {
      $matches = [regex]::Matches($rawResponse, $patterns[$key], 'IgnoreCase,Multiline')
      if ($matches.Count -gt 0) {
        $values = $matches | ForEach-Object { $_.Groups[$_.Groups.Count - 1].Value.Trim() } | Select-Object -Unique
        $whoisData[$key] = $values -join ', '
      }
    }
    
    # Special handling for name servers (collect all)
    $nsMatches = [regex]::Matches($rawResponse, 'Name Server:\s*(.+)', 'IgnoreCase,Multiline')
    if ($nsMatches.Count -gt 0) {
      $whoisData['Name Servers'] = ($nsMatches | ForEach-Object { $_.Groups[1].Value.Trim().ToLower() } | Select-Object -Unique) -join ', '
    }
  } catch {
    $success = $false
    $errorMsg = $_.Exception.Message
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  if ($success) {
    $summaryRows = @(@('Domain', $domain))
    foreach ($key in @('Registrar', 'Creation Date', 'Expiration Date', 'Updated Date', 'Status', 'Name Servers')) {
      if ($whoisData.ContainsKey($key)) {
        $val = $whoisData[$key]
        if ($val.Length -gt 60) { $val = $val.Substring(0, 60) + '...' }
        $summaryRows += ,@($key, $val)
      }
    }
    
    Write-XY @{ table = @{ title='WHOIS Information'; header=@('Property','Value'); rows=$summaryRows; caption="Data from WHOIS server" } }
    
    # Show raw response preview
    $preview = if ($rawResponse.Length -gt 1500) { $rawResponse.Substring(0, 1500) + "`n... (truncated)" } else { $rawResponse }
    Write-XY @{ text = @{ title='Raw WHOIS Response'; content=$preview; caption='' } }
    
    [pscustomobject]@{ tool='WHOIS Lookup'; domain=$domain; success=$true; registrar=$whoisData['Registrar']; creationDate=$whoisData['Creation Date']; expirationDate=$whoisData['Expiration Date']; updatedDate=$whoisData['Updated Date']; nameServers=$whoisData['Name Servers']; status=$whoisData['Status']; rawResponse=$rawResponse }
  } else {
    Write-XY @{ table = @{ title='WHOIS Error'; header=@('Property','Value'); rows=@(@('Domain', $domain), @('Error', $errorMsg)); caption='Lookup failed' } }
    [pscustomobject]@{ tool='WHOIS Lookup'; domain=$domain; success=$false; error=$errorMsg }
  }
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
    'ipAddressTools' { $result = Invoke-IPAddressTools -Params $params -JobInput $jobInput }
    'jwtDecoder'     { $result = Invoke-JWTDecoder -Params $params -JobInput $jobInput }
    'pingTest'       { $result = Invoke-PingTest -Params $params -JobInput $jobInput }
    'dnsLookup'      { $result = Invoke-DnsLookup -Params $params -JobInput $jobInput }
    'traceroute'     { $result = Invoke-Traceroute -Params $params -JobInput $jobInput }
    'portScanner'    { $result = Invoke-PortScanner -Params $params -JobInput $jobInput }
    'httpChecker'    { $result = Invoke-HttpChecker -Params $params -JobInput $jobInput }
    'sslChecker'     { $result = Invoke-SslChecker -Params $params -JobInput $jobInput }
    'whoisLookup'    { $result = Invoke-WhoisLookup -Params $params -JobInput $jobInput }
    default          { throw "Unknown tool: $tool" }
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
