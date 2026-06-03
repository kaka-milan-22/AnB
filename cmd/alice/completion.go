package main

import (
	"fmt"
	"sort"

	"github.com/kaka-milan-22/AnB/v3/internal/localvault"
)

// commandsForCompletion lists the user-facing subcommands offered as the
// first-argument completion. Kept here (not derived from the dispatch map) so
// the hidden helpers (__complete-keys) stay out of completion.
var commandsForCompletion = []string{
	"read", "write", "has", "list", "status", "exec",
	"set", "get", "rm", "desc", "import", "gen",
	"init", "scan", "template", "shell",
	"rekey", "rekey-status", "backfill-meta", "audit",
	"enroll", "install-cert", "allowlist-check", "eth",
	"completion",
}

// keyTakingCommands complete an existing secret key name as their argument.
var keyTakingCommands = "get|rm|desc|has"

// completion <zsh|bash> — print a shell completion script. The script
// completes subcommands, and for key-taking commands completes existing key
// names by shelling back into `alice __complete-keys`.
func cmdCompletion(args []string) error {
	fs := newFS("completion")
	pos := parse(fs, args)
	shell := "zsh"
	if len(pos) > 0 {
		shell = pos[0]
	}
	switch shell {
	case "zsh":
		fmt.Printf(zshCompletion, joinWords(commandsForCompletion), keyTakingCommands)
	case "bash":
		fmt.Printf(bashCompletion, joinWords(commandsForCompletion), keyTakingCommands)
	default:
		return fmt.Errorf("unsupported shell %q (use: zsh | bash)", shell)
	}
	return nil
}

// __complete-keys — hidden: print stored key names, one per line, for dynamic
// completion. Not listed in usage or the completion command set.
func cmdCompleteKeys(args []string) error {
	fs := newFS("__complete-keys")
	dir := dirFlag(fs)
	parse(fs, args)
	v, err := localvault.Open(*dir).Load()
	if err != nil {
		return nil // stay silent: completion must never error out the shell
	}
	for _, l := range v.List() {
		fmt.Println(l.Key)
	}
	return nil
}

func joinWords(ws []string) string {
	out := make([]string, len(ws))
	copy(out, ws)
	sort.Strings(out)
	s := ""
	for i, w := range out {
		if i > 0 {
			s += " "
		}
		s += w
	}
	return s
}

const zshCompletion = `#compdef alice
# alice shell completion. Install:  alice completion zsh > "${fpath[1]}/_alice"  (then restart zsh)
_alice() {
  local -a cmds
  cmds=(%s)
  if (( CURRENT == 2 )); then
    compadd -- $cmds
    return
  fi
  case ${words[2]} in
    %s)
      compadd -- ${(f)"$(alice __complete-keys 2>/dev/null)"}
      ;;
  esac
}
compdef _alice alice
`

const bashCompletion = `# alice bash completion. Install:  alice completion bash > /usr/local/etc/bash_completion.d/alice
#   or:  source <(alice completion bash)
_alice() {
  local cur cmds
  cur="${COMP_WORDS[COMP_CWORD]}"
  cmds="%s"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
    return
  fi
  case "${COMP_WORDS[1]}" in
    %s)
      COMPREPLY=( $(compgen -W "$(alice __complete-keys 2>/dev/null)" -- "$cur") )
      ;;
  esac
}
complete -F _alice alice
`
