package umbra

import (
	"net"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultLoginServerAddr(t *testing.T) {
	assert.Equal(t, "login.us.wizard101.com:12000", DefaultLoginServerAddr())
}

func TestDefaultPatchServerAddr(t *testing.T) {
	addr := DefaultPatchServerAddr()

	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	assert.Equal(t, "patch.us.wizard101.com", host)

	// Same host serving the platform's build variant
	want := "12500"
	if runtime.GOOS == "darwin" {
		want = "12600"
	}
	assert.Equal(t, want, port)
}

func TestParentDirs(t *testing.T) {
	dirs := parentDirs("a/b/c")
	assert.Equal(t, []string{"a", "a/b", "a/b/c"}, dirs)

	dirs = parentDirs("a/b")
	assert.Equal(t, []string{"a", "a/b"}, dirs)

	dirs = parentDirs("a")
	assert.Equal(t, []string{"a"}, dirs)

	dirs = parentDirs("a/b/../c")
	assert.Equal(t, []string{"a", "a/c"}, dirs)
}
