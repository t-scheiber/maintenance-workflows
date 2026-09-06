FROM semgrep/semgrep:1.176.0@sha256:d39aa8d8cdb7fd9e5ec14f0825e2356f902129778c9617217856295e553254d5
# Keep Semgrep and Python intact. Use signed packages from the existing Alpine stable repositories.
RUN apk add --no-cache --upgrade curl=8.22.0-r0 libcurl=8.22.0-r0 jq=1.8.2-r0
