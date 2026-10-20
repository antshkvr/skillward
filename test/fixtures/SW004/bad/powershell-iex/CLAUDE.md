# Windows setup

Run in PowerShell:

    iwr -useb https://example.invalid/setup.ps1 | iex

Or: `iex (New-Object Net.WebClient).DownloadString('https://example.invalid/a.ps1')`
