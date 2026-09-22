# Run every fuzz target for N seconds each (default 60) and summarise.
# Needs the nightly toolchain, cargo-fuzz, and the MSVC ASan runtime on PATH.
param([int]$Seconds = 60)
$msvc = Get-ChildItem "C:\Program Files (x86)\Microsoft Visual Studio\*\BuildTools\VC\Tools\MSVC\*\bin\Hostx64\x64" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
$env:Path = "$env:USERPROFILE\.cargo\bin;$msvc;$env:Path"
Set-Location $PSScriptRoot
$targets = @("eth","vlan","llc","arp","ipv4","ipv6","icmp","icmpv6","udp","tcp","dns","dhcp","http","tls","frame","pcapng")
$results = @()
foreach ($t in $targets) {
    $out = cargo +nightly fuzz run $t -- "-max_total_time=$Seconds" -max_len=4096 2>&1
    $code = $LASTEXITCODE
    $done = ($out | Select-String -Pattern "Done (\d+) runs" | Select-Object -Last 1)
    $runs = if ($done) { $done.Matches[0].Groups[1].Value } else { "?" }
    $cov = ($out | Select-String -Pattern "cov: (\d+)" | Select-Object -Last 1)
    $edges = if ($cov) { $cov.Matches[0].Groups[1].Value } else { "?" }
    $crash = ($out | Select-String -Pattern "panicked at|deadly signal|timeout after|out-of-memory" | Select-Object -First 1)
    $status = if ($code -eq 0) { "ok" } else { "FAIL" }
    $results += ("{0,-8} {1,-5} runs={2,-8} edges={3,-6} {4}" -f $t, $status, $runs, $edges, $(if ($crash) { $crash.Line.Trim() } else { "" }))
}
$results
