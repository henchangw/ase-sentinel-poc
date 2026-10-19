# Local checks for protected-range canonicalization. No Azure connection.
. (Join-Path $PSScriptRoot 'ip-ranges.ps1')

$failures = [System.Collections.Generic.List[string]]::new()

function Assert-Equal {
    param($Name, $Actual, $Expected)
    if ($Actual -ne $Expected) {
        $script:failures.Add("${Name}: expected [$Expected] actual [$Actual]")
    }
}

function Assert-Throws {
    param($Name, [scriptblock] $Script)
    $threw = $false
    try { & $Script } catch { $threw = $true }
    if (-not $threw) { $script:failures.Add("${Name}: expected a throw") }
}

Assert-Equal 'v4 /8' (ConvertTo-CanonicalIpRange '10.0.0.0/8') '10.0.0.0/8'
Assert-Equal 'v4 host' (ConvertTo-CanonicalIpRange '192.0.2.10') '192.0.2.10'
Assert-Equal 'v4 /32' (ConvertTo-CanonicalIpRange '203.0.113.5/32') '203.0.113.5/32'
Assert-Throws 'v4 /12' { ConvertTo-CanonicalIpRange '172.16.0.0/12' }
Assert-Throws 'v4 /10' { ConvertTo-CanonicalIpRange '100.64.0.0/10' }
Assert-Throws 'v4 leading zero' { ConvertTo-CanonicalIpRange '192.168.001.1' }
Assert-Throws 'v4 space' { ConvertTo-CanonicalIpRange '192.0.2.10 ' }

$expanded = '2001:0db8:0000:0000:0000:0000:0000:0001'
Assert-Equal 'v6 compressed' (ConvertTo-CanonicalIpRange '2001:db8::1') $expanded
Assert-Equal 'v6 uppercase' (ConvertTo-CanonicalIpRange '2001:DB8::1') $expanded
Assert-Equal 'v6 /32' (ConvertTo-CanonicalIpRange '2001:db8::/32') '2001:0db8:0000:0000:0000:0000:0000:0000/32'
Assert-Equal 'v6 /32 keeps host bits' (ConvertTo-CanonicalIpRange '2001:db8::1/32') "$expanded/32"
Assert-Equal 'v6 /64' (ConvertTo-CanonicalIpRange '2001:db8:1:2::/64') '2001:0db8:0001:0002:0000:0000:0000:0000/64'
Assert-Throws 'v6 /10 customer prefix' { ConvertTo-CanonicalIpRange 'fe80::/10' }
Assert-Throws 'v6 /7 customer prefix' { ConvertTo-CanonicalIpRange 'fc00::/7' }
Assert-Throws 'v6 /40' { ConvertTo-CanonicalIpRange '2001:db8::/40' }
Assert-Throws 'mapped dotted' { ConvertTo-CanonicalIpRange '::ffff:192.0.2.1' }
Assert-Throws 'mapped expanded' { ConvertTo-CanonicalIpRange '0000:0000:0000:0000:0000:ffff:c000:0201' }
Assert-Throws 'zone id' { ConvertTo-CanonicalIpRange 'fe80::1%12' }

Assert-Equal 'loopback ::1' (Get-AseBuiltInProtection (ConvertTo-CanonicalIpRange '::1')) 'loopback'
Assert-Equal 'unspecified ::' (Get-AseBuiltInProtection (ConvertTo-CanonicalIpRange '::')) 'unspecified'
Assert-Equal 'fe80::/10' (Get-AseBuiltInProtection (ConvertTo-CanonicalIpRange 'fe80::1')) 'link-local'
Assert-Equal 'febf still link-local' (Get-AseBuiltInProtection (ConvertTo-CanonicalIpRange 'febf::1')) 'link-local'
Assert-Equal 'fec0 is not link-local' (Get-AseBuiltInProtection (ConvertTo-CanonicalIpRange 'fec0::1')) $null
Assert-Equal 'fc00 ula' (Get-AseBuiltInProtection (ConvertTo-CanonicalIpRange 'fc00::1')) 'unique-local'
Assert-Equal 'fd00 ula' (Get-AseBuiltInProtection (ConvertTo-CanonicalIpRange 'fd12:3456::1')) 'unique-local'
Assert-Equal 'public v6' (Get-AseBuiltInProtection $expanded) $null
Assert-Equal 'cgnat stays protected' (Get-AseBuiltInProtection '100.64.1.1') 'cgnat'
Assert-Equal 'public v4' (Get-AseBuiltInProtection '203.0.113.5') $null
Assert-Equal 'rfc1918' (Get-AseBuiltInProtection '10.1.2.3') 'rfc1918'

Assert-Equal 'v6 /32 ignores host bits' (Test-AseCustomerRangeCovers $expanded '2001:0db8:0009:0000:0000:0000:0000:0099/32') $true
Assert-Equal 'v6 /32 same two groups' (Test-AseCustomerRangeCovers $expanded '2001:0db8:0000:0000:0000:0000:0000:0000/32') $true
Assert-Equal 'v6 /32 other net' (Test-AseCustomerRangeCovers $expanded '2001:0db9:0000:0000:0000:0000:0000:0000/32') $false
Assert-Equal 'v4 /24' (Test-AseCustomerRangeCovers '203.0.113.5' '203.0.113.0/24') $true
Assert-Equal 'v4 /24 miss' (Test-AseCustomerRangeCovers '203.0.113.5' '203.0.114.0/24') $false
Assert-Equal 'v4 does not cover v6' (Test-AseCustomerRangeCovers $expanded '203.0.113.0/16') $false

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$workflow = Get-Content -Raw (Join-Path $repoRoot 'playbooks/block-malicious-ip/workflow.json')
foreach ($marker in @(
        'Application Gateway IPMatch does not enforce IPv6',
        'rejected: IPv4-mapped IPv6',
        'fe80',
        'febf',
        'fc00',
        'fdff',
        '112',
        '128'
    )) {
    if ($workflow -notlike "*$marker*") { $failures.Add("workflow.json is missing $marker") }
}
if ($workflow -match 'not an IPv4 address') { $failures.Add('workflow.json still rejects every IPv6 shape as non-IPv4') }

$queries = Get-ChildItem (Join-Path $repoRoot 'sentinel/analytics-rules/*.kql')
foreach ($query in $queries) {
    $text = Get-Content -Raw $query.FullName
    if ($text -notmatch 'parse_ipv6\(') { $failures.Add("$($query.Name) does not call parse_ipv6") }
    if ($text -match 'not\(ClientIp has ":"\)') { $failures.Add("$($query.Name) still drops every address that contains a colon") }
    if ($text -notmatch 'BuiltInProtectedV6') { $failures.Add("$($query.Name) has no IPv6 built-in list") }
    if ($text -notmatch '0000:0000:0000:0000:0000:ffff:') { $failures.Add("$($query.Name) does not convert IPv4-mapped addresses") }
}

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ }
    exit 1
}
Write-Output "ip range checks passed ($($queries.Count) analytics queries)"
