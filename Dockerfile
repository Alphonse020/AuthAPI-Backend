# ===== Build stage =====
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build 
WORKDIR /src 
COPY AuthApi.sln . 
COPY AuthApi/*.csproj ./AuthApi/ 
RUN dotnet restore 
COPY . . 
WORKDIR /src/AuthApi 
