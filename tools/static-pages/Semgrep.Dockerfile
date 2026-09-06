FROM semgrep/semgrep:1.176.0@sha256:12672acdb0949e19f9f6a4c2b288edd0b404f268f0ca7738a2c06f372f50362e
# Keep Semgrep and Python intact. Use signed packages from the existing Alpine stable repositories.
RUN apk add --no-cache --upgrade curl=8.22.0-r0 libcurl=8.22.0-r0 jq=1.8.2-r0
