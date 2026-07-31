# ADRot — read-only Active Directory hygiene scanner.
#
# Primarily useful for the offline workflow: capture a snapshot on a domain-joined
# host with Export-ADRotSnapshot, then analyse it anywhere, including on a Linux CI
# runner with no line of sight to the domain.
#
# A LIVE scan from inside this container needs a Kerberos or NTLM identity, which a
# Linux container does not have by default. For live scans, run ADRot directly on a
# domain-joined machine.
FROM mcr.microsoft.com/powershell:7.4-debian-12

LABEL org.opencontainers.image.title="ADRot" \
      org.opencontainers.image.description="Read-only Active Directory hygiene and security scanner" \
      org.opencontainers.image.source="https://github.com/MisterMobilka/adrot" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /opt/adrot
COPY src/ /opt/adrot/src/
COPY docker/entrypoint.ps1 /opt/adrot/entrypoint.ps1

# Fail the build rather than ship an image whose module does not load.
RUN pwsh -NoProfile -Command " \
      Import-Module /opt/adrot/src/ADRot/ADRot.psd1 -Force -ErrorAction Stop; \
      \$n = (Get-Command -Module ADRot).Count; \
      if (\$n -ne 3) { throw \"Expected 3 exported commands, got \$n\" }; \
      Write-Host \"ADRot module verified: \$n commands\" "

# Run as a non-root user: ADRot only ever reads, so it needs no privileges at all.
RUN useradd --create-home --shell /usr/sbin/nologin adrot
USER adrot

ENTRYPOINT ["pwsh", "-NoProfile", "-NonInteractive", "-File", "/opt/adrot/entrypoint.ps1"]
CMD ["-Help"]
