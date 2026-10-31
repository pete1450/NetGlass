#!/bin/sh
# Publish the Windows agent exe from any machine with the .NET SDK.
# Produces out/win-x64/NetGlass.Agent.exe — single file, self-contained.
set -e
dotnet publish src/NetGlass.Agent/NetGlass.Agent.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o out/win-x64
echo "Built: out/win-x64/NetGlass.Agent.exe"
