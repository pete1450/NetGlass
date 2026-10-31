FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY src/NetGlass.Agent/*.csproj src/NetGlass.Agent/
RUN dotnet restore src/NetGlass.Agent/NetGlass.Agent.csproj
COPY src/NetGlass.Agent/ src/NetGlass.Agent/
RUN dotnet publish src/NetGlass.Agent/NetGlass.Agent.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/runtime:8.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish ./
# The agent needs the host's /proc at /host/proc (PROC_ROOT) and
# pid: host (see the compose generator output). It listens on nothing.
ENV PROC_ROOT=/host/proc
ENTRYPOINT ["dotnet", "NetGlass.Agent.dll"]
