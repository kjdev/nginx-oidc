# Installation

Build and installation instructions for the nginx OIDC module.

## Prerequisites

### Required Libraries

- **nginx**: 1.18.0 or later
- **OpenSSL**: 3.0.0 or later (for JWT signature verification)
- **PCRE**: 8.x or later (for regular expression processing)
- **zlib**: 1.2.x or later (for compression processing)
- **jansson**: 2.x or later (for JSON processing)
- **hiredis**: 1.0.0 or later (for Redis session store; always required at build time)

### Package Installation Examples

**Debian/Ubuntu**:
```bash
apt-get install -y \
    build-essential \
    libssl-dev \
    libpcre3-dev \
    zlib1g-dev \
    libjansson-dev \
    libhiredis-dev
```

**RHEL/CentOS/Fedora**:
```bash
dnf install -y \
    gcc \
    make \
    openssl-devel \
    pcre-devel \
    zlib-devel \
    jansson-devel \
    hiredis-devel
```

## Building from Source

### Step 1: Obtain the nginx Source Code

Extract the nginx source code under the OIDC module repository root. The directory structure should look like this:

```
nginx-oidc/          # OIDC module repository root
├── src/
├── nginx-x.y.z/     # nginx source code (run configure inside this directory)
│   └── ...
└── ...
```

```bash
# Download the nginx source code (adjust the version as needed)
wget https://nginx.org/download/nginx-x.y.z.tar.gz
tar -xzf nginx-x.y.z.tar.gz
cd nginx-x.y.z
```

### Step 2: Run configure

```bash
./configure \
    --with-compat \
    --with-debug \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-pcre \
    --with-pcre-jit \
    --add-dynamic-module=..
```

**Required options**:
- `--with-compat`: Enable dynamic module compatibility
- `--with-http_ssl_module`: Enable HTTPS and SSL/TLS related features (required for TLS communication with the OIDC provider)
- `--add-dynamic-module`: Build the OIDC module as a dynamic module (`..` refers to the parent directory = repository root)

**Recommended options**:
- `--with-debug`: Enable debug logging (recommended during development and debugging)
- `--with-http_v2_module`: Enable HTTP/2
- `--with-pcre` / `--with-pcre-jit`: Enable PCRE regular expression support

### Step 3: Build

```bash
make
```

### Step 4: Verify the Module

Upon successful build, the dynamic module will be generated:

```bash
ls -l objs/ngx_http_oidc_module.so
```

### Step 5: Load the Module

Add the following to the top level of the nginx configuration file (typically `/etc/nginx/nginx.conf`):

```nginx
load_module "/path/to/objs/ngx_http_oidc_module.so";
```

### Step 6: Validate Configuration and Start

```bash
# Validate configuration
nginx -t

# Start nginx
nginx
```

**Note**:
- This guide covers only the basic build procedure
- For system installation (`make install`), please proceed according to your environment

## Docker

You can build nginx with the module using Docker images.

```bash
# Build the Docker image
docker build --target module -t nginx-oidc .

# Start the container
docker run -d -p 80:80 \
    -v /path/to/default.conf:/etc/nginx/conf.d/default.conf:ro \
    nginx-oidc
```

The Dockerfile is preconfigured to automatically load the module.

## Related Documents

- [README.md](../README.md): Module overview
- [DIRECTIVES.md](DIRECTIVES.md): Directive and variable reference
- [EXAMPLES.md](EXAMPLES.md): Quick start and practical configuration examples
- [SECURITY.md](SECURITY.md): Security considerations (PKCE, HTTPS, cookie security, etc.)
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): Troubleshooting (common issues, log inspection)
- [JWT_SUPPORTED_ALGORITHMS.md](JWT_SUPPORTED_ALGORITHMS.md): JWT supported algorithms
- [COMMERCIAL_COMPATIBILITY.md](COMMERCIAL_COMPATIBILITY.md): Commercial edition compatibility
