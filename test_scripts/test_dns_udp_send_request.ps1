param($readfile, $dnsserver, $enable_output_logfile)

if ((-Not $readfile) -Or (-Not $dnsserver)) {
    Write-Host "Usage) "$MyInvocation.MyCommand.Name"[testdata.txt] [dnsserver] [TRUE | FALSE]"
    exit
}

if (-Not(Test-Path $readfile)) {
    Write-Host "$readfile is not exist."
    exit
}

if (-Not $enable_output_logfile) {
    $ENABLE_OUTPUT_LOG = $FALSE
}
else {
    if ($enable_output_logfile.ToUpper() -eq "TRUE") {
        $ENABLE_OUTPUT_LOG = $TRUE
    }
    else {
        $ENABLE_OUTPUT_LOG = $FALSE
    }
}

$target_program = "../dns_send_udp_request.py"
$records = (Get-Content $readfile) -as [string[]]

Write-Host "DNSSERVER = $dnsserver\n"

if ($ENABLE_OUTPUT_LOG) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logfile = "./log/result_" + $timestamp + ".log"

    if (Test-Path $logfile) {
        Write-Host "$lofile is exist."
        exit
    }

    Write-Host "LOGFILE = $logfile"

    foreach($record in $records) {
        $resolvstr, $record = $record -split " "
        Write-Host "Execute: python $target_program $dnsserver $resolvstr $record  | Out-File -Append $logfile -Encoding ascii"
        python $target_program $dnsserver $resolvstr $record | Out-File -Append $logfile -Encoding ascii
    }
}
else {
    foreach($record in $records) {
        $resolvstr, $record = $record -split " "
        Write-Host "Execute: python $target_program $dnsserver $resolvstr $record"
        python $target_program $dnsserver $resolvstr $record
    }
}
