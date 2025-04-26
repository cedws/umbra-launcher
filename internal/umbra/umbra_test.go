package umbra

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
