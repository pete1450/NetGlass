# Server: Node builds the React UI, .NET builds the server, ASP.NET runtime serves both.
FROM node:20-slim AS web
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm install --no-audit --no-fund || npm install --no-audit --no-fund --legacy-peer-deps
COPY web/ ./
RUN npm run build

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY src/NetGlass.Server/*.csproj src/NetGlass.Server/
RUN dotnet restore src/NetGlass.Server/NetGlass.Server.csproj
COPY src/NetGlass.Server/ src/NetGlass.Server/
RUN dotnet publish src/NetGlass.Server/NetGlass.Server.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
# apprise is optional: if present, the server uses it for notifications.
RUN apt-get update && apt-get install -y --no-install-recommends apprise 2>/dev/null || true; rm -rf /var/lib/apt/lists/*
COPY --from=build /app/publish ./
COPY --from=web /web/dist ./wwwroot
ENV ASPNETCORE_URLS=http://+:8080
ENV NETGLASS_DB=/data/netglass.db
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["dotnet", "NetGlass.Server.dll"]
