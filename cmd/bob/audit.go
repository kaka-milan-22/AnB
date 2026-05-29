package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/kaka-milan-22/AnB/v2/internal/server"
)

// newJSONEmitter returns a server.Emitter that writes one JSON object per
// line to w. Each line carries an RFC3339Nano `ts` and a string `kind`,
// then the caller's flat key,value,... payload. v2.5+ format.
//
// Writes are serialized via mu so concurrent goroutines (one per Bob
// connection) don't interleave bytes on a single line.
func newJSONEmitter(w io.Writer) server.Emitter {
	var mu sync.Mutex
	return func(kind string, kv ...any) {
		payload := make(map[string]any, 2+len(kv)/2)
		payload["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
		payload["kind"] = kind
		for i := 0; i+1 < len(kv); i += 2 {
			k, ok := kv[i].(string)
			if !ok {
				continue
			}
			payload[k] = kv[i+1]
		}
		b, err := json.Marshal(payload)
		if err != nil {
			// Final fallback — should never happen with sane callers.
			b = []byte(fmt.Sprintf(`{"ts":%q,"kind":"AUDIT_ENCODE_FAIL","err":%q}`,
				time.Now().UTC().Format(time.RFC3339Nano), err.Error()))
		}
		mu.Lock()
		defer mu.Unlock()
		_, _ = w.Write(append(b, '\n'))
	}
}
