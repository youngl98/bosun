package collectors

import (
	"fmt"
	"io"
	"math/big"

	"bosun.org/_third_party/github.com/mjibson/snmp"
	"bosun.org/cmd/scollector/conf"
	"bosun.org/metadata"
	"bosun.org/opentsdb"
)

var builtInSNMPs = map[string]func(cfg conf.SNMP){"ifaces": SNMPIfaces, "cisco": SNMPCisco}

func SNMP(cfg conf.SNMP, mibs map[string]conf.MIB) error {
	if cfg.Host == "" {
		return fmt.Errorf("empty SNMP hostname")
	}
	if cfg.Community == "" {
		return fmt.Errorf("empty SNMP community")
	}
	if len(cfg.MIBs) == 0 {
		cfg.MIBs = []string{"ifaces", "cisco"}
	}
	for _, m := range cfg.MIBs {

		mib, ok := mibs[m]
		if ok {
			collectors = append(collectors, &IntervalCollector{
				F: func() (opentsdb.MultiDataPoint, error) {
					return c_snmp_generic(cfg, mib)
				},
				name: fmt.Sprintf("snmp-generic-%s-%s", cfg.Host, m),
			})
		} else {
			if f, ok := builtInSNMPs[m]; ok {
				f(cfg)
			} else {
				return fmt.Errorf("unknown MIB \"%s\" specified", m)
			}
		}
	}
	return nil
}

// snmp_subtree takes an oid and returns all data exactly one level below it. It
// produces an error if there is more than one level below.
func snmp_subtree(host, community, oid string) (map[int]interface{}, error) {
	rows, err := snmp.Walk(host, community, oid)
	if err != nil {
		return nil, err
	}
	m := make(map[int]interface{})
	for rows.Next() {
		switch oid {
		case ifHCInBroadcastPkts:
			a := new(big.Int)
			id, err := rows.Scan(&a)
			if err != nil {
				return nil, err
			}
			switch t := id.(type) {
			case int:
				m[t] = a
			default:
				return nil, fmt.Errorf("snmp subtree: only one level allowed")
			}
		default:
			var a interface{}
			id, err := rows.Scan(&a)
			if err != nil {
				return nil, err
			}
			switch t := id.(type) {
			case int:
				m[t] = a
			default:
				return nil, fmt.Errorf("snmp subtree: only one level allowed")
			}
		}
	}
	if err := rows.Err(); err != nil && err != io.EOF {
		return nil, err
	}
	return m, nil
}

func snmp_oid(host, community, oid string) (*big.Int, error) {
	v := new(big.Int)
	err := snmp.Get(host, community, oid, &v)
	return v, err
}

func combineOids(oid, base string) string {
	if oid != "" && oid[0] == '.' {
		return base + oid
	}
	return oid
}

func c_snmp_generic(cfg conf.SNMP, mib conf.MIB) (opentsdb.MultiDataPoint, error) {
	md := opentsdb.MultiDataPoint{}
	baseOid := mib.BaseOid

	for _, metric := range mib.Metrics {
		rate := metadata.RateType(metric.RateType)
		if rate == "" {
			rate = metadata.Gauge
		}
		unit := metadata.Unit(metric.Unit)
		if unit == "" {
			unit = metadata.None
		}
		tagset := opentsdb.TagSet{"host": cfg.Host}

		v, err := snmp_oid(cfg.Host, cfg.Community, combineOids(metric.Oid, baseOid))
		if err != nil && metric.FallbackOid != "" {
			v, err = snmp_oid(cfg.Host, cfg.Community, combineOids(metric.FallbackOid, baseOid))
		}
		if err != nil {
			return md, err
		}
		Add(&md, metric.Metric, v, tagset, rate, unit, metric.Description)
	}
	for _, tree := range mib.Trees {
		treeOid := combineOids(tree.BaseOid, baseOid)
		tagCache := make(map[string]map[int]interface{}) // tag key to map of values
		for _, tag := range tree.Tags {
			if tag.Oid == "idx" {
				continue
			}
			vals, err := snmp_subtree(cfg.Host, cfg.Community, combineOids(tag.Oid, treeOid))
			if err != nil {
				return md, err
			}
			tagCache[tag.Key] = vals
		}
		for _, metric := range tree.Metrics {
			tagset, err := opentsdb.ParseTags(metric.Tags)
			if err != nil {
				fmt.Println("AAAAA")
				return md, err
			}
			tagset["host"] = cfg.Host
			rate := metadata.RateType(metric.RateType)
			if rate == "" {
				rate = metadata.Gauge
			}
			unit := metadata.Unit(metric.Unit)
			if unit == "" {
				unit = metadata.None
			}
			fmt.Println(combineOids(metric.Oid, treeOid))
			nodes, err := snmp_subtree(cfg.Host, cfg.Community, combineOids(metric.Oid, treeOid))
			if err != nil {
				fmt.Println("BBBBBB")
				return md, err
			}
			// check all lengths
			for k, list := range tagCache {
				if len(list) != len(nodes) {
					return md, fmt.Errorf("snmp tree for tag key %s, and metric %s do not have same length", k, metric.Metric)
				}
			}
			for i, v := range nodes {

				for _, tag := range tree.Tags {
					var tagVal interface{}
					if tag.Oid == "idx" {
						tagVal = i
					} else {
						var ok bool
						tagVal, ok = tagCache[tag.Key][i]
						if !ok {
							fmt.Println("CCCCCC")
							return md, fmt.Errorf("tree for tag %s has no entry for metric %s index %d.", tag.Key, metric.Metric, i)
						}
					}
					tagset[tag.Key] = fmt.Sprint(tagVal)
				}
				Add(&md, metric.Metric, v, tagset, rate, unit, metric.Description)
			}
		}
	}
	return md, nil
}
