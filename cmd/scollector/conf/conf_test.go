package conf

import (
	"bytes"
	"testing"

	"bosun.org/_third_party/github.com/BurntSushi/toml"
)

// build a data structure and serialize it. This is easier sometimes than building by hand.
func TestMIBSerialization(t *testing.T) {

	m := MIB{}
	m.BaseOid = "1.3.6.1.2.1.33.1"
	m.Trees = []MIBTree{
		{
			BaseOid: ".3.3.1",
			Tags:    []MIBTag{{Key: "source", Oid: "idx"}},
			Metrics: []MIBMetric{
				{Oid: ".3", Metric: "environment.power.voltage", Tags: "direction=input"},
				{Oid: ".2", Metric: "environment.power.frequancy", Tags: "direction=input"},
			},
		},
	}

	conf := Conf{}
	conf.MIBS = map[string]MIB{"ups": m}

	buf := &bytes.Buffer{}
	err := toml.NewEncoder(buf).Encode(conf)
	if err != nil {
		t.Fatal(err)
	}
	//println(buf.String())
}
