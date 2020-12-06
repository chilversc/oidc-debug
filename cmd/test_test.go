package cmd

import (
	"bytes"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/chilversc/oidc-debug/internal/testmock"
	"github.com/stretchr/testify/require"
)

func TestTest(t *testing.T) {
	ts := testmock.Serve()
	defer ts.Close()

	cfg := TestConfig{
		IssuerURL:    ts.URL + "/",
		ClientID:     "testing",
		ClientSecret: "123456",
		ClientPort:   4447,
		OpenURL:      testmock.OpenURL,
	}

	r, err := redirectOutput()
	defer r.close()
	require.NoError(t, err)

	Test(cfg)
	stdout, _ := r.stop()

	require.Contains(t, stdout, `"sub": "someone@test"`)
}

// This is temporary, need to change the test function to return some
// kind of report structure that can be inspected.
type redirect struct {
	stdout *stream
	stderr *stream
	wg     *sync.WaitGroup
}

type stream struct {
	original *os.File
	replaced *os.File
	capture  string
}

func (r *redirect) close() {
	if r == nil {
		return
	}
	if r.stdout != nil {
		os.Stdout = r.stdout.original
		r.stdout.replaced.Close()
	}
	if r.stderr != nil {
		os.Stderr = r.stderr.original
		r.stderr.replaced.Close()
	}
}

func (r *redirect) stop() (string, string) {
	r.close()
	r.wg.Wait()
	return r.stdout.capture, r.stderr.capture
}

func redirectOutput() (*redirect, error) {
	r := &redirect{}
	r.wg = &sync.WaitGroup{}
	r.wg.Add(2)

	stdout, err := newStream(os.Stdout, r.wg)
	r.stdout = stdout
	if err != nil {
		r.close()
		return nil, err
	}

	stderr, err := newStream(os.Stderr, r.wg)
	r.stderr = stderr
	if err != nil {
		r.close()
		return nil, err
	}

	os.Stdout = r.stdout.replaced
	os.Stderr = r.stderr.replaced

	return r, err
}

func newStream(original *os.File, wg *sync.WaitGroup) (*stream, error) {
	r, w, err := os.Pipe()
	s := &stream{original, w, ""}

	// Tee the reader so that every thing we read into the buffer
	// is also echoed to the original output stream.
	// The test runner has better output for multiple lines wrote
	// to stdout/err compared to the assersion error message.
	t := io.TeeReader(r, original)

	go func() {
		buf := &bytes.Buffer{}
		io.Copy(buf, t)
		s.capture = buf.String()
		wg.Done()
	}()

	return s, err
}
