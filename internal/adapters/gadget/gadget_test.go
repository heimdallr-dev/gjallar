package gadget

import (
	"strings"
	"testing"
)

// Trimmed from real `kubectl gadget run trace_open:v0.58.0 -A -o json` output (containerd, kind).
const events = `{"error":"","error_raw":0,"fd":3,"fname":"/lib/x86_64-linux-gnu/libc.so.6","k8s":{"containerName":"web4","namespace":"demo","node":"gjallar-control-plane","podName":"web4"},"proc":{"comm":"nginx"},"runtime":{"containerImageDigest":"","containerImageName":"nginx:1.27","runtimeName":"containerd"}}
{"error":"ENOENT","error_raw":2,"fname":"/lib/x86_64-linux-gnu/libnope.so","k8s":{"containerName":"web4","namespace":"demo","podName":"web4"}}
{"error":"","error_raw":0,"fname":"/var/lib/kubelet/x","k8s":{"containerName":"","namespace":"","podName":""}}
not json
`

func TestParseKeepsSuccessfulPodOpens(t *testing.T) {
	var got []Open
	if err := Parse(strings.NewReader(events), func(o Open) { got = append(got, o) }); err != nil {
		t.Fatal(err)
	}
	want := Open{Namespace: "demo", Pod: "web4", Container: "web4", Path: "/lib/x86_64-linux-gnu/libc.so.6"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %+v", got)
	}
}
