package main

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// decodeTree renders a frame layer by layer, one field per line, then a hex dump.
func decodeTree(raw []byte, lt layers.LinkType) []string {
	if len(raw) == 0 {
		return []string{"bytes no longer kept: this packet has left the 5000-packet buffer"}
	}
	pkt := gopacket.NewPacket(raw, lt, gopacket.Default)
	var lines []string
	for _, l := range pkt.Layers() {
		hdr := len(l.LayerContents())
		lines = append(lines, fmt.Sprintf("▸ %s  (%d byte header, %d byte payload)", l.LayerType(), hdr, len(l.LayerPayload())))
		lines = append(lines, layerFields(l)...)
		lines = append(lines, "")
	}
	if e := pkt.ErrorLayer(); e != nil {
		lines = append(lines, "decode error: "+e.Error().Error(), "")
	}
	lines = append(lines, fmt.Sprintf("▸ Hex dump  (%d bytes)", len(raw)))
	for _, l := range strings.Split(strings.TrimRight(hex.Dump(raw), "\n"), "\n") {
		lines = append(lines, "  "+l)
	}
	return lines
}

// layerFields lists the exported fields of a layer struct, skipping the raw
// Contents/Payload that every layer embeds.
func layerFields(l gopacket.Layer) []string {
	v := reflect.ValueOf(l)
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return []string{"  " + fmt.Sprint(l)}
	}
	var out []string
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		ft := t.Field(i)
		if ft.PkgPath != "" { // unexported
			continue
		}
		if ft.Anonymous && ft.Type == reflect.TypeOf(layers.BaseLayer{}) {
			continue
		}
		fv := v.Field(i)
		out = append(out, fmt.Sprintf("  %-18s %s", ft.Name, fieldString(fv)))
	}
	return out
}

func fieldString(v reflect.Value) string {
	if v.CanInterface() {
		if s, ok := v.Interface().(fmt.Stringer); ok && v.Kind() != reflect.Ptr {
			if str := s.String(); str != "" {
				return str
			}
			return "(none)"
		}
	}
	switch v.Kind() {
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			b := v.Bytes()
			if len(b) == 0 {
				return "(none)"
			}
			if ip := toAddr(b); (len(b) == 4 || len(b) == 16) && ip.IsValid() {
				return ip.String()
			}
			if len(b) > 24 {
				return fmt.Sprintf("%d bytes: % x …", len(b), b[:24])
			}
			return fmt.Sprintf("% x", b)
		}
		if v.Len() == 0 {
			return "(none)"
		}
		var parts []string
		for i := 0; i < v.Len() && i < 8; i++ {
			parts = append(parts, fmt.Sprint(v.Index(i).Interface()))
		}
		if v.Len() > 8 {
			parts = append(parts, fmt.Sprintf("… %d more", v.Len()-8))
		}
		return strings.Join(parts, "; ")
	case reflect.Ptr:
		if v.IsNil() {
			return "(none)"
		}
		return fmt.Sprint(v.Elem().Interface())
	}
	return fmt.Sprint(v.Interface())
}
