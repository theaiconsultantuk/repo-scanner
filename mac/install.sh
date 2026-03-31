#!/usr/bin/env bash
# GitHub Repository Security Scanner — macOS Installer
set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  GitHub Repo Security Scanner${NC}"
echo -e "${CYAN}  macOS Installer${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# ── 1. Homebrew ──────────────────────────────────────────────
if ! command -v brew &>/dev/null; then
  echo -e "${YELLOW}Installing Homebrew...${NC}"
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  # Add brew to PATH for Apple Silicon
  if [[ -f /opt/homebrew/bin/brew ]]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
    echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
  fi
else
  echo -e "${GREEN}✓ Homebrew already installed${NC}"
fi

# ── 2. Bun (runtime for the scanner) ─────────────────────────
if ! command -v bun &>/dev/null; then
  echo -e "${YELLOW}Installing Bun...${NC}"
  curl -fsSL https://bun.sh/install | bash
  export BUN_INSTALL="$HOME/.bun"
  export PATH="$BUN_INSTALL/bin:$PATH"
  # Persist to shell profile
  for profile in ~/.zshrc ~/.bashrc ~/.bash_profile; do
    if [[ -f "$profile" ]]; then
      echo 'export BUN_INSTALL="$HOME/.bun"' >> "$profile"
      echo 'export PATH="$BUN_INSTALL/bin:$PATH"' >> "$profile"
    fi
  done
else
  echo -e "${GREEN}✓ Bun already installed${NC}"
fi

# ── 3. GitHub CLI ─────────────────────────────────────────────
if ! command -v gh &>/dev/null; then
  echo -e "${YELLOW}Installing GitHub CLI...${NC}"
  brew install gh
else
  echo -e "${GREEN}✓ GitHub CLI already installed${NC}"
fi

# ── 4. Security scanning tools ───────────────────────────────
echo ""
echo -e "${YELLOW}Installing security tools (this may take a few minutes)...${NC}"

TOOLS=(scorecard grype syft gitleaks trufflehog semgrep osv-scanner)
for tool in "${TOOLS[@]}"; do
  if command -v "$tool" &>/dev/null; then
    echo -e "  ${GREEN}✓ $tool already installed${NC}"
  else
    echo -e "  Installing $tool..."
    brew install "$tool" 2>&1 | tail -1
    echo -e "  ${GREEN}✓ $tool installed${NC}"
  fi
done

# ── 5. GuardDog (Python) ──────────────────────────────────────
if ! command -v guarddog &>/dev/null; then
  echo -e "${YELLOW}Installing GuardDog...${NC}"
  if command -v pipx &>/dev/null; then
    pipx install guarddog
  elif command -v pip3 &>/dev/null; then
    pip3 install guarddog --user
  else
    brew install pipx
    pipx install guarddog
  fi
  echo -e "${GREEN}✓ GuardDog installed${NC}"
else
  echo -e "${GREEN}✓ GuardDog already installed${NC}"
fi

# ── 6. Install scanner ────────────────────────────────────────
INSTALL_DIR="$HOME/.repo-scanner"
mkdir -p "$INSTALL_DIR/scans"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "$SCRIPT_DIR/../scanner/scan.ts" "$INSTALL_DIR/scan.ts"

# Create the `repo-scan` command
cat > "$INSTALL_DIR/repo-scan" << 'WRAPPER'
#!/usr/bin/env bash
BUN_INSTALL="${HOME}/.bun"
PATH="${BUN_INSTALL}/bin:/opt/homebrew/bin:/usr/local/bin:${PATH}"
SCANNER_DIR="${HOME}/.repo-scanner"
exec bun run "${SCANNER_DIR}/scan.ts" "$@"
WRAPPER
chmod +x "$INSTALL_DIR/repo-scan"

# Symlink to /usr/local/bin (or ~/bin if no write access)
if [[ -w /usr/local/bin ]]; then
  ln -sf "$INSTALL_DIR/repo-scan" /usr/local/bin/repo-scan
  echo -e "${GREEN}✓ 'repo-scan' command installed to /usr/local/bin${NC}"
else
  mkdir -p "$HOME/bin"
  ln -sf "$INSTALL_DIR/repo-scan" "$HOME/bin/repo-scan"
  # Ensure ~/bin is in PATH
  for profile in ~/.zshrc ~/.bashrc ~/.bash_profile; do
    if [[ -f "$profile" ]] && ! grep -q 'HOME/bin' "$profile"; then
      echo 'export PATH="$HOME/bin:$PATH"' >> "$profile"
    fi
  done
  echo -e "${GREEN}✓ 'repo-scan' command installed to ~/bin${NC}"
fi

# ── 7. GitHub auth check ──────────────────────────────────────
echo ""
if gh auth status &>/dev/null; then
  echo -e "${GREEN}✓ GitHub CLI authenticated${NC}"
  # Set GITHUB_TOKEN for scorecard
  GH_TOKEN=$(gh auth token 2>/dev/null || true)
  if [[ -n "$GH_TOKEN" ]]; then
    for profile in ~/.zshrc ~/.bashrc ~/.bash_profile; do
      if [[ -f "$profile" ]] && ! grep -q 'GITHUB_TOKEN' "$profile"; then
        echo "# Set by repo-scanner installer" >> "$profile"
        echo 'export GITHUB_TOKEN=$(gh auth token 2>/dev/null)' >> "$profile"
      fi
    done
  fi
else
  echo -e "${YELLOW}⚠ GitHub CLI not authenticated.${NC}"
  echo -e "  Run: ${CYAN}gh auth login${NC}"
  echo -e "  (Required for full Scorecard scans — free GitHub account is fine)"
fi

# ── Done ──────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Installation complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Usage:"
echo -e "  ${CYAN}repo-scan https://github.com/owner/repo${NC}         # Full scan"
echo -e "  ${CYAN}repo-scan https://github.com/owner/repo --quick${NC} # Remote only (fast)"
echo -e "  ${CYAN}repo-scan https://github.com/owner/repo --json${NC}  # JSON output"
echo ""
echo -e "${YELLOW}Note: Open a new terminal tab for the 'repo-scan' command to be available.${NC}"
echo ""
