# Homebrew cask for CybX NetworkLens.
#
# Lets Mac users install and update with:
#     brew tap cybx-security/tap
#     brew install --cask cybx-networklens
#     brew upgrade --cask cybx-networklens
#
# To publish: create a public repository named "homebrew-tap" in the
# cybx-security organization, put this file at Casks/cybx-networklens.rb,
# and after each release update `version` and the two sha256 values (from
# the release's SHA256SUMS; arm first, then intel). Regenerate the values with:
#     python packaging/homebrew/update_cask.py 1.3.0
cask "cybx-networklens" do
  version "1.3.0"
  sha256 arm:   "REPLACE_WITH_ARM64_DMG_SHA256",
         intel: "REPLACE_WITH_X86_64_DMG_SHA256"

  url "https://github.com/cybx-security/CybX-NetworkLens/releases/download/v#{version}/CybXNetworkLens-#{version}-macos-#{Hardware::CPU.arm? ? "arm64" : "x86_64"}.dmg"
  name "CybX NetworkLens"
  desc "Network scanner that finds devices, open ports and risky services, with offline risk analysis"
  homepage "https://github.com/cybx-security/CybX-NetworkLens"

  app "CybX NetworkLens.app"
  binary "networklens"

  zap trash: [
    "~/.config/cybx-networklens",
    "~/Library/Logs/CybX NetworkLens",
  ]
end
