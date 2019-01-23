#!/usr/bin/env sh

brew install swiftformat
mkdir .git/hooks/
echo "#!/bin/bash
git diff --staged --name-only | grep -e '\(.*\).swift$' | while read line; do
  swiftformat \"\${line}\" --enable blankLinesBetweenScopes,blankLinesAroundMark,blankLinesAtStartOfScope,blankLinesAtEndOfScope --indent 2 --wraparguments beforefirst --wrapcollections beforefirst --empty void --commas inline --patternlet hoist --semicolons inline --enable trailingClosures;
  git add \"\${line}\";
done" > .git/hooks/pre-commit
chmod 775 .git/hooks/pre-commit