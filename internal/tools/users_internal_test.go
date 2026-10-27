package tools

import (
	"reflect"
	"testing"
)

func TestPickFleets(t *testing.T) {
	all := []string{"a", "b", "c"}
	for _, c := range []struct {
		want, got []string
	}{
		{nil, all},
		{[]string{"a"}, []string{"a"}},
		{[]string{"c", "a"}, []string{"a", "c"}},
	} {
		got, err := pickFleets(all, c.want)
		if err != nil || !reflect.DeepEqual(got, c.got) {
			t.Errorf("pickFleets(%v) = %v, %v; want %v", c.want, got, err, c.got)
		}
	}
	if _, err := pickFleets(all, []string{"a", "x"}); err == nil {
		t.Error("unknown fleet accepted")
	}
}
