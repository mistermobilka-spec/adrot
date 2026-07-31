# ADRot task runner.
#
# Every target works on Windows, Linux and macOS as long as PowerShell 7 (pwsh)
# is on PATH. On Windows, run these from Git Bash or WSL; the PowerShell
# equivalents are printed by `make help`.

PWSH    ?= pwsh -NoProfile -NonInteractive -Command
MODULE  := ./src/ADRot/ADRot.psd1
OUT     := ./out

.DEFAULT_GOAL := help
.PHONY: help bootstrap lint test test-unit test-integration check demo report clean \
        docker-build docker-demo ldap-up ldap-down

help: ## Show this help
	@echo "ADRot — read-only Active Directory hygiene scanner"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Without make, run the same steps directly:"
	@echo "  pwsh -c 'Invoke-Pester ./tests/unit'"
	@echo "  pwsh -c 'Invoke-ScriptAnalyzer -Path ./src -Recurse -Settings ./PSScriptAnalyzerSettings.psd1'"

bootstrap: ## Install the PowerShell modules needed to lint and test
	$(PWSH) "Set-PSRepository PSGallery -InstallationPolicy Trusted; \
	  foreach (\$$m in @(@{N='Pester';V='6.0.0'},@{N='PSScriptAnalyzer';V='1.22.0'})) { \
	    if (-not (Get-Module -ListAvailable \$$m.N | Where-Object Version -ge \$$m.V)) { \
	      Write-Host \"Installing \$$(\$$m.N)\"; \
	      Install-Module \$$m.N -MinimumVersion \$$m.V -Scope CurrentUser -Force -AllowClobber } \
	    else { Write-Host \"\$$(\$$m.N) already present\" } }"

lint: ## Run PSScriptAnalyzer over src and tests
	$(PWSH) "\$$issues = @(); \
	  foreach (\$$p in @('./src','./tests')) { \
	    \$$issues += Invoke-ScriptAnalyzer -Path \$$p -Recurse -Settings ./PSScriptAnalyzerSettings.psd1 }; \
	  if (\$$issues) { \$$issues | Format-Table Severity,RuleName,ScriptName,Line,Message -AutoSize -Wrap; \
	    throw \"\$$(\$$issues.Count) lint issue(s)\" } else { Write-Host 'Lint clean.' -ForegroundColor Green }"

test: test-unit ## Alias for test-unit

test-unit: ## Run the unit test suite
	$(PWSH) "\$$c = New-PesterConfiguration; \
	  \$$c.Run.Path = './tests/unit'; \$$c.Run.Exit = \$$true; \
	  \$$c.Output.Verbosity = 'Detailed'; \
	  \$$c.TestResult.Enabled = \$$true; \$$c.TestResult.OutputPath = './TestResults.xml'; \
	  Invoke-Pester -Configuration \$$c"

test-integration: ## Run integration tests against the LDAP container (needs Docker)
	$(PWSH) "\$$c = New-PesterConfiguration; \
	  \$$c.Run.Path = './tests/integration'; \$$c.Run.Exit = \$$true; \
	  \$$c.Output.Verbosity = 'Detailed'; \
	  Invoke-Pester -Configuration \$$c"

check: lint test-unit ## Lint and unit-test — what CI runs

demo: ## Scan the bundled rotten fixture and print the terminal report
	$(PWSH) "Import-Module $(MODULE) -Force; \
	  Invoke-ADRotScan -SnapshotPath ./tests/fixtures/dirty-domain.json -InformationAction SilentlyContinue"

report: ## Generate out/demo-report.html from the rotten fixture
	$(PWSH) "New-Item -ItemType Directory -Force -Path $(OUT) | Out-Null; \
	  Import-Module $(MODULE) -Force; \
	  Invoke-ADRotScan -SnapshotPath ./tests/fixtures/dirty-domain.json \
	    -HtmlPath $(OUT)/demo-report.html -JsonPath $(OUT)/demo-report.json \
	    -Quiet -InformationAction SilentlyContinue; \
	  Write-Host 'Wrote $(OUT)/demo-report.html'"

ldap-up: ## Start the seeded test LDAP server
	docker compose -f docker/docker-compose.yml up -d --build --wait

ldap-down: ## Stop and remove the test LDAP server
	docker compose -f docker/docker-compose.yml down -v

docker-build: ## Build the ADRot container image
	docker build -f docker/Dockerfile -t adrot:local .

docker-demo: docker-build ## Run the demo scan inside the container
	docker run --rm -v "$(CURDIR)/tests/fixtures:/fixtures:ro" adrot:local \
	  -SnapshotPath /fixtures/dirty-domain.json

clean: ## Remove generated output
	$(PWSH) "Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $(OUT), ./TestResults.xml"
