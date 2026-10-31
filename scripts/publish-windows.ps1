# Publish the Windows agent exe (run on Windows, in PowerShell, from the repo root).
# Produces out/win-x64/NetGlass.Agent.exe — single file, self-contained.
# First run: double-click it, enter server URL + token when prompted.
dotnet publish src/NetGlass.Agent/NetGlass.Agent.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o out/win-x64
Write-Host "Built: out/win-x64/NetGlass.Agent.exe"
