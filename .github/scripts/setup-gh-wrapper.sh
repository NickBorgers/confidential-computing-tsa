#!/bin/bash
# Programmatic bot marker injection: wrap gh so all comments
# automatically get the <!-- bot:claude-workflow --> marker appended.
# This prevents feedback loops where Claude-authored comments
# could re-trigger the Claude workflow.
#
# Usage: source this script before invoking Claude in any workflow.
# It replaces `gh` on PATH with a wrapper that intercepts
# `gh pr comment` and `gh issue comment` to append the marker.

REAL_GH="$(which gh)"
cat > /tmp/gh-wrapper << 'GHWRAPPER'
#!/bin/bash
MARKER=$'\n<!-- bot:claude-workflow -->'
# Intercept 'gh pr comment' and 'gh issue comment' to append marker
if { [ "${1:-}" = "pr" ] && [ "${2:-}" = "comment" ]; } || \
   { [ "${1:-}" = "issue" ] && [ "${2:-}" = "comment" ]; }; then
  args=()
  i=1
  while [ $i -le $# ]; do
    arg="${!i}"
    args+=("$arg")
    if [ "$arg" = "--body" ]; then
      i=$((i + 1))
      val="${!i}"
      # Append marker if not already present
      if ! echo "$val" | grep -qF '<!-- bot:claude-workflow -->'; then
        val="${val}${MARKER}"
      fi
      args+=("$val")
    fi
    i=$((i + 1))
  done
  exec "__REAL_GH__" "${args[@]}"
else
  exec "__REAL_GH__" "$@"
fi
GHWRAPPER
sed -i "s|__REAL_GH__|${REAL_GH}|g" /tmp/gh-wrapper
chmod +x /tmp/gh-wrapper
export PATH="/tmp:$PATH"
ln -sf /tmp/gh-wrapper /tmp/gh
