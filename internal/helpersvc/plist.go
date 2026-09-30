package helpersvc

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
)

// renderPlist is the launchd job: root runs args at boot and again whenever
// it exits, logging to log.
func renderPlist(args []string, log string) []byte {
	var b bytes.Buffer
	str := func(s string) string {
		var e bytes.Buffer
		xml.EscapeText(&e, []byte(s))
		return "<string>" + e.String() + "</string>"
	}
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	` + str(Label) + `
	<key>ProgramArguments</key>
	<array>
`)
	for _, a := range args {
		b.WriteString("\t\t" + str(a) + "\n")
	}
	b.WriteString(`	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	` + str(log) + `
	<key>StandardErrorPath</key>
	` + str(log) + `
</dict>
</plist>
`)
	return b.Bytes()
}

type plistNode struct {
	XMLName  xml.Name
	Text     string      `xml:",chardata"`
	Children []plistNode `xml:",any"`
}

// parsePlist reads a flat launchd plist: string, boolean and string-array
// values keyed by name.
func parsePlist(data []byte) (map[string]any, error) {
	var root plistNode
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("launchd plist: %w", err)
	}
	if root.XMLName.Local != "plist" || len(root.Children) != 1 || root.Children[0].XMLName.Local != "dict" {
		return nil, fmt.Errorf("launchd plist: want one top-level dict")
	}
	items := root.Children[0].Children
	if len(items)%2 != 0 {
		return nil, fmt.Errorf("launchd plist: unpaired key")
	}
	out := map[string]any{}
	for i := 0; i < len(items); i += 2 {
		key, value := items[i], items[i+1]
		if key.XMLName.Local != "key" {
			return nil, fmt.Errorf("launchd plist: %s where a key belongs", key.XMLName.Local)
		}
		if _, dup := out[key.Text]; dup {
			return nil, fmt.Errorf("launchd plist: duplicate key %s", key.Text)
		}
		switch value.XMLName.Local {
		case "string":
			out[key.Text] = value.Text
		case "true", "false":
			out[key.Text], _ = strconv.ParseBool(value.XMLName.Local)
		case "array":
			var list []string
			for _, c := range value.Children {
				if c.XMLName.Local != "string" {
					return nil, fmt.Errorf("launchd plist: %s holds a %s", key.Text, c.XMLName.Local)
				}
				list = append(list, c.Text)
			}
			out[key.Text] = list
		default:
			return nil, fmt.Errorf("launchd plist: %s is a %s", key.Text, value.XMLName.Local)
		}
	}
	return out, nil
}

// programArguments is the installed job's command line.
func programArguments(data []byte) ([]string, error) {
	plist, err := parsePlist(data)
	if err != nil {
		return nil, err
	}
	args, ok := plist["ProgramArguments"].([]string)
	if !ok || len(args) < 2 || args[1] != "run" {
		return nil, fmt.Errorf("launchd plist: ProgramArguments is not a helper run command")
	}
	return args, nil
}

// flagValue returns the value of the single name flag in a run command line
// made of flag/value pairs.
func flagValue(args []string, name string) (string, error) {
	if len(args)%2 != 0 {
		return "", fmt.Errorf("launchd plist: ProgramArguments are not flag/value pairs")
	}
	var value string
	found := false
	for i := 2; i < len(args); i += 2 {
		if args[i] != name {
			continue
		}
		if found {
			return "", fmt.Errorf("launchd plist: %s appears twice", name)
		}
		value, found = args[i+1], true
	}
	if !found {
		return "", fmt.Errorf("launchd plist: %s is missing", name)
	}
	return value, nil
}
