# Canonical form and built-in classification for protected IP ranges.
# The playbook in playbooks/block-malicious-ip/workflow.json accepts this same form.
# IPv4 stays dotted decimal with no leading zeros.
# IPv6 is eight lowercase groups of four hex digits, the parse_ipv6() shape.
# Customer prefixes the playbook can compare: IPv4 /8 /16 /24 /32, IPv6 hextet boundaries.

$script:AseIpRangeHelp = 'IPv4 entries must be a single canonical address or /8, /16, /24, or /32. IPv6 entries must be an address or /16, /32, /48, /64, /80, /96, /112, or /128. IPv4-mapped IPv6 is rejected. 172.16.0.0/12 and 100.64.0.0/10 are already built in.'

function Format-CanonicalIPv6 {
    param([Parameter(Mandatory)][System.Net.IPAddress] $Address)
    $bytes = $Address.GetAddressBytes()
    $groups = for ($index = 0; $index -lt 16; $index += 2) {
        $value = ([int] $bytes[$index] -shl 8) -bor [int] $bytes[$index + 1]
        '{0:x4}' -f $value
    }
    return ($groups -join ':')
}

function ConvertTo-CanonicalIpRange {
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Entry)
    if ([string]::IsNullOrWhiteSpace($Entry) -or $Entry -match '[\s,%]') {
        throw "Protected range '$Entry' is not usable. $script:AseIpRangeHelp"
    }
    $pieces = $Entry.Split('/')
    if ($pieces.Count -gt 2 -or [string]::IsNullOrEmpty($pieces[0])) {
        throw "Protected range '$Entry' is not usable. $script:AseIpRangeHelp"
    }
    $addressText = $pieces[0]
    $prefix = $null
    if ($pieces.Count -eq 2) {
        if ($pieces[1] -notmatch '^(?:8|16|24|32|48|64|80|96|112|128)$') {
            throw "Protected range '$Entry' uses a prefix this playbook cannot compare. $script:AseIpRangeHelp"
        }
        $prefix = [int] $pieces[1]
    }
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($addressText, [ref] $parsed)) {
        throw "Protected range '$Entry' is not an IP address. $script:AseIpRangeHelp"
    }
    if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        if ($null -ne $prefix -and $prefix -notin 8, 16, 24, 32) {
            throw "Protected range '$Entry' uses an IPv4 prefix this playbook cannot compare. $script:AseIpRangeHelp"
        }
        $canonical = $parsed.ToString()
        if ($canonical -cne $addressText) {
            throw "Protected range '$Entry' is not a canonical IPv4 address. $script:AseIpRangeHelp"
        }
        if ($null -eq $prefix) { return $canonical }
        return "$canonical/$prefix"
    }
    if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($parsed.IsIPv4MappedToIPv6) {
            throw "Protected range '$Entry' is an IPv4-mapped IPv6 address. Submit the IPv4 address. $script:AseIpRangeHelp"
        }
        if ($null -ne $prefix -and $prefix -notin 16, 32, 48, 64, 80, 96, 112, 128) {
            throw "Protected range '$Entry' uses an IPv6 prefix this playbook cannot compare. $script:AseIpRangeHelp"
        }
        $canonical = Format-CanonicalIPv6 -Address $parsed
        if ($null -eq $prefix) { return $canonical }
        return "$canonical/$prefix"
    }
    throw "Protected range '$Entry' is not usable. $script:AseIpRangeHelp"
}

function Get-AseBuiltInProtection {
    param([Parameter(Mandatory)][string] $CanonicalAddress)
    if ($CanonicalAddress -match '^\d+\.\d+\.\d+\.\d+$') {
        $octets = $CanonicalAddress.Split('.')
        $first = [int] $octets[0]
        $second = [int] $octets[1]
        if ($first -eq 0) { return 'unspecified' }
        if ($first -eq 10 -or ($first -eq 172 -and $second -ge 16 -and $second -le 31) -or ($first -eq 192 -and $second -eq 168)) { return 'rfc1918' }
        if ($first -eq 127) { return 'loopback' }
        if ($first -eq 169 -and $second -eq 254) { return 'link-local' }
        if ($first -eq 100 -and $second -ge 64 -and $second -le 127) { return 'cgnat' }
        return $null
    }
    $groups = $CanonicalAddress.Split(':')
    if ($groups.Count -ne 8) { return $null }
    if (@($groups | Where-Object { $_ -ne '0000' }).Count -eq 0) { return 'unspecified' }
    if (@($groups[0..6] | Where-Object { $_ -ne '0000' }).Count -eq 0 -and $groups[7] -eq '0001') { return 'loopback' }
    if ($groups[0] -ge 'fe80' -and $groups[0] -le 'febf') { return 'link-local' }
    if ($groups[0] -ge 'fc00' -and $groups[0] -le 'fdff') { return 'unique-local' }
    return $null
}

function Test-AseCustomerRangeCovers {
    param(
        [Parameter(Mandatory)][string] $CanonicalAddress,
        [Parameter(Mandatory)][string] $CanonicalRange
    )
    if ($CanonicalRange -eq $CanonicalAddress) { return $true }
    if ($CanonicalRange -notlike '*/*') { return $false }
    $rangeAddress, $prefixText = $CanonicalRange.Split('/')
    $prefix = [int] $prefixText
    $addressIsV6 = $CanonicalAddress.Contains(':')
    $rangeIsV6 = $rangeAddress.Contains(':')
    if ($addressIsV6 -ne $rangeIsV6) { return $false }
    if ($addressIsV6) {
        $take = @{ 16 = 1; 32 = 2; 48 = 3; 64 = 4; 80 = 5; 96 = 6; 112 = 7; 128 = 8 }[$prefix]
        if (-not $take) { return $false }
        $left = ($CanonicalAddress.Split(':')[0..($take - 1)] -join ':')
        $right = ($rangeAddress.Split(':')[0..($take - 1)] -join ':')
        return $left -eq $right
    }
    $take = @{ 8 = 1; 16 = 2; 24 = 3; 32 = 4 }[$prefix]
    if (-not $take) { return $false }
    $left = ($CanonicalAddress.Split('.')[0..($take - 1)] -join '.')
    $right = ($rangeAddress.Split('.')[0..($take - 1)] -join '.')
    return $left -eq $right
}
