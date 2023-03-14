#!/bin/sh

# Any subsequent commands that fail cause the shellscript to exit immediately.
set -e

# The default GitHub action schedule runs this on the default branch.
# In our action we run this script multiple times for any branch that requires converted rules for a specific uberAgent version.
# Determine the current branch and switch if needed.
CURRENT_BRANCH=`git rev-parse --abbrev-ref HEAD`

if [[ "$1" == "" ]]; then
    echo "error: Script is missing branch parameter as first positional argument"
    exit 1
fi

if [[ "$1" != $CURRENT_BRANCH ]]; then
    git fetch
    CURRENT_BRANCH=$1
    echo "info: Use branch $CURRENT_BRANCH"
    git checkout $CURRENT_BRANCH 2>/dev/null || git checkout -b $CURRENT_BRANCH
fi

# setup git
git config --global user.email "github.action@localhost.local"
git config --global user.name "vastlimits"
git config --global --add safe.directory /github/workspace

# checkout our fork of the sigma project (including the newest converter)
git clone --branch feature/uberAgent-backend-macOS-integration https://github.com/vastlimits/sigma.git

# navigate to sigma directory for further git commands
cd sigma

# add sigma remote and fetch
git remote add sigma https://github.com/SigmaHQ/sigma.git
git fetch sigma

# rebase our working copy on the latest sigma branch
git rebase sigma/master

# remove files causing crashes
rm rules/windows/builtin/security/win_security_successful_external_remote_rdp_login.yml
rm rules/windows/builtin/security/win_security_successful_external_remote_smb_login.yml

# navigate to sigmac
cd tools

# set target version
if [[ "$CURRENT_BRANCH" == "develop" ]]; then
    echo "info: Use $CURRENT_BRANCH as output version"
    sed -i "s/main/$CURRENT_BRANCH/" config/uberagent.yml
elif [[ "$CURRENT_BRANCH" == "main" ]]; then
    echo "info: Use $CURRENT_BRANCH as output version"
    # Do not modify configuration because main is set by default anyways.
elif [[ "$CURRENT_BRANCH" == version* ]]; then
    CURRENT_BRANCH=${CURRENT_BRANCH:8}
    echo "info: Use $CURRENT_BRANCH as output version"
    sed -i "s/main/$CURRENT_BRANCH/" config/uberagent.yml
else
    echo "error: Unknown version <$CURRENT_BRANCH> to generate rules for"
    exit 1
fi

# upgrade pip installation
python -m pip install --upgrade pip

# install dependencies
pip install requests
pip install markdown
pip install markdown-link-attr-modifier
pip install PyYAML
pip install pymisp
pip install progressbar2
pip install ruamel.yaml
pip install termcolor
pip install sigma

# begin converting rules as usual
python sigmac -I --target uberagent -r ../rules/ --backend-config config/uberagent.yml

# navigate back
cd ../../

# delete any earlier sigma rule files first
# this is required to easily support file name changes and delete orphaned files
git rm config/uberAgent-ESA-am-sigma-*.conf || true

# new branches, create directory if it does not yet exist
mkdir -p config

# copy current converted configuration
cp -v sigma/tools/uberAgent-ESA-am-sigma-*.conf config/

# clean up sigma checkout
rm -f -r sigma/

# push changes
echo "machine github.com" > "$HOME/.netrc"
echo "  login $GITHUB_ACTOR" >> "$HOME/.netrc"
echo "  password $GITHUB_TOKEN" >> "$HOME/.netrc"

echo "machine api.github.com" >> "$HOME/.netrc"
echo "  login $GITHUB_ACTOR" >> "$HOME/.netrc"
echo "  password $GITHUB_TOKEN" >> "$HOME/.netrc"

git add config/*.conf
git commit -m "Updated converted sigma rules for version $CURRENT_BRANCH"

git config --global --add --bool push.autoSetupRemote true || true
git push

echo "info: Convert sigma rules to uberAgent ESA rules for version $CURRENT_BRANCH finished"
exit 0
