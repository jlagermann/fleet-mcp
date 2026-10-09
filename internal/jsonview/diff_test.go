package jsonview

import (
	"encoding/json"
	"testing"
)

func TestDiff(t *testing.T) {
	a := doc(t, `{"name":"p","n":1,"cfg":{"x.y":true,"gone":1},"list":[1,2],"long":[1]}`)
	b := doc(t, `{"name":"p","n":2,"cfg":{"x.y":false,"new":"v"},"list":[1,3],"long":[1,2]}`)
	got, trunc := Diff(a, b, 0)
	bs, _ := json.Marshal(got)
	want := `[{"path":"/cfg/gone","op":"remove","from":1},{"path":"/cfg/new","op":"add","to":"v"},{"path":"/cfg/x.y","op":"change","from":true,"to":false},{"path":"/list/1","op":"change","from":2,"to":3},{"path":"/long","op":"change","from":[1],"to":[1,2]},{"path":"/n","op":"change","from":1,"to":2}]`
	if trunc || string(bs) != want {
		t.Fatalf("got %s (trunc %v)\nwant %s", bs, trunc, want)
	}
	if d, _ := Diff(a, a, 0); len(d) != 0 {
		t.Fatalf("self diff: %v", d)
	}
	if d, trunc := Diff(a, b, 2); len(d) != 2 || !trunc {
		t.Fatalf("limit: %v %v", d, trunc)
	}
}
