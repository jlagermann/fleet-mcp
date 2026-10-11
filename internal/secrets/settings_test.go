package secrets

import "testing"

func TestSettingSecrets(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	name := "exporter:Splunk Prod:hec_token"
	if _, err := s.GetSetting("exporter:Splunk:hec_token"); err == nil {
		t.Fatal("missing secret found")
	}
	if err := s.SetSetting(name, " tok \n"); err != nil {
		t.Fatal(err)
	}
	if v, err := s.GetSetting(name); err != nil || v != "tok" {
		t.Fatalf("%q %v", v, err)
	}
	if err := s.DeleteSetting(name); err != nil || s.HasSetting(name) {
		t.Fatal("not deleted")
	}
	for _, bad := range []string{"../x", "a/b", ""} {
		if err := s.SetSetting(bad, "v"); err == nil {
			t.Errorf("bad name %q accepted", bad)
		}
	}
}
