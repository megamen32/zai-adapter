package zsign

import (
	"os"
	"strings"
)

func readKey() (string, string, error) {
	raw, _ := os.ReadFile("/home/roomhacker/.zcode/v2/config.json")
	s := string(raw)
	i := strings.Index(s, `"builtin:zai-coding-plan"`)
	r := s[i:]
	k := r[strings.Index(r, `"apiKey"`)+8:]
	k = k[strings.Index(k, `"`)+1:]
	k = k[:strings.Index(k, `"`)]
	return k, "", nil
}
