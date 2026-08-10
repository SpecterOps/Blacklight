# Scout build image: MinGW (Windows BOF + EXE), gcc (Linux .so),
# Python/Make, and .NET SDK 8 (managed Apollo EXE).
# Host only needs Docker; macOS dylib remains Darwin-only.
FROM mcr.microsoft.com/dotnet/sdk:8.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        make \
        gcc \
        g++ \
        libc6-dev \
        mingw-w64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY docker-entrypoint.sh /usr/local/bin/scout-build
RUN chmod +x /usr/local/bin/scout-build

ENTRYPOINT ["/usr/local/bin/scout-build"]
