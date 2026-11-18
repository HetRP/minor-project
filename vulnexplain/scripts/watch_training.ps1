$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$projectRoot = Split-Path -Parent $PSScriptRoot
$metricsPath = Join-Path $projectRoot 'results\training_log.csv'
$runLogPath = Join-Path $projectRoot 'results\training_50_epochs.log'
$notificationLog = Join-Path $projectRoot 'results\epoch_notifications.log'
$tray = New-Object System.Windows.Forms.NotifyIcon
$tray.Icon = [System.Drawing.SystemIcons]::Information
$tray.Text = 'VulnExplain training'
$tray.Visible = $true
$lastMilestone = 5
try {
    while ($lastMilestone -lt 50) {
        if (Test-Path -LiteralPath $metricsPath) {
            $rows = @(Import-Csv -LiteralPath $metricsPath)
            foreach ($milestone in @(10, 15, 20, 25, 30, 35, 40, 45, 50)) {
                if ($milestone -le $lastMilestone) { continue }
                $row = $rows | Where-Object { [int]$_.epoch -eq $milestone } | Select-Object -First 1
                if ($null -eq $row) { break }
                $message = "Epoch $milestone/50 complete. Validation F1: $($row.val_f1)."
                $tray.ShowBalloonTip(15000, 'VulnExplain training progress', $message, [System.Windows.Forms.ToolTipIcon]::Info)
                Add-Content -LiteralPath $notificationLog -Value "$(Get-Date -Format o) $message"
                $lastMilestone = $milestone
                Start-Sleep -Seconds 16
            }
        }
        if (Test-Path -LiteralPath $runLogPath) {
            $tail = Get-Content -LiteralPath $runLogPath -Tail 30
            if ($tail -match '^Traceback \(most recent call last\):|^torch.OutOfMemoryError:|^RuntimeError:') {
                $tray.ShowBalloonTip(15000, 'VulnExplain training stopped', 'Training reported an error. Check results/training_50_epochs.log.', [System.Windows.Forms.ToolTipIcon]::Error)
                Add-Content -LiteralPath $notificationLog -Value "$(Get-Date -Format o) Training error detected."
                Start-Sleep -Seconds 16
                break
            }
        }
        Start-Sleep -Seconds 30
    }
} finally {
    $tray.Dispose()
}
