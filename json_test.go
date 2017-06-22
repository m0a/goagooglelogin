package goagooglelogin

import (
	"encoding/json"
	"testing"
)

func TestJson(t *testing.T) {
	// var data []byte
	strs := []string{}
	data, err := json.Marshal(strs)
	if err != nil {
		t.Error(err)
	}

	t.Errorf("data=%s;\n", string(data))
}
