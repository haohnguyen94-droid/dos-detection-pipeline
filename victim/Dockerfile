# ─────────────────────────────────────────────────────────────────────────────
# Victim Container — nginx web server with passive packet capture
# ─────────────────────────────────────────────────────────────────────────────
# Role in the pipeline: the target of simulated DoS attacks. Runs a standard
# nginx server on port 80 while tcpdump silently records every packet that
# touches the container's interfaces. The resulting .pcap is written to the
# shared /pcaps volume where the detector will read it in the Beta milestone.
# ─────────────────────────────────────────────────────────────────────────────

# Base image: nginx 1.25 on Alpine Linux.
# Alpine is used instead of the default Debian-based nginx image because it's
# ~5x smaller (~40MB vs ~200MB), which means faster builds and pulls. The
# tradeoff is that Alpine uses `apk` as its package manager and `musl` libc
# instead of `glibc`, so some commands and flags differ from Ubuntu/Debian.
FROM nginx:1.25-alpine

# Install tcpdump (packet capture tool) and bash (optional, for easier
# debugging if we ever `docker exec` into the container).
#   apk add          → Alpine's package install command
#   --no-cache       → don't keep the package index on disk; keeps image small
#   tcpdump          → the capture tool invoked by entrypoint.sh
RUN apk add --no-cache tcpdump

# Set the working directory inside the image. All subsequent COPY and RUN
# commands are relative to this path, and a shell opened in this container
# will start here. Using /victim (matching the service name) makes it obvious
# which container you're in when debugging.
WORKDIR /victim

# Copy everything from the build context (the ./victim folder on the host)
# into the current WORKDIR inside the image. This brings in entrypoint.sh,
# nginx.conf (when we add it), and any other files in victim/.
COPY . .

# Ensure entrypoint.sh is executable. This is critical on Windows/WSL
# filesystems, which don't preserve Unix permission bits reliably — without
# this line you may get "permission denied" when the container starts.
RUN chmod +x /victim/entrypoint.sh

# launches tcpdump in the background, then execs nginx in the foreground so
# nginx becomes PID 1 and owns the container lifecycle (container lives as
# long as nginx lives, and `docker stop` signals nginx directly).
CMD ["/victim/entrypoint.sh"]
