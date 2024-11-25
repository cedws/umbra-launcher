package umbra

import (
	"context"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"math/bits"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/cedws/w101-client-go/dml"
	crypto "github.com/cedws/w101-client-go/login"
	"github.com/cedws/w101-client-go/proto"
	"github.com/cedws/w101-proto-go/pkg/login"
	"github.com/cedws/w101-proto-go/pkg/patch"
	"github.com/saferwall/pe"
	"github.com/spf13/afero"
	"golang.org/x/sync/errgroup"
)

const (
	fileTypeExecutable = 4
	fileTypeDynamicWAD = 5
)

var (
	errTimeoutAuthenRsp = fmt.Errorf("timed out waiting for authen response")
	errTimeoutFileList  = fmt.Errorf("timed out waiting for latest file list")
)

var (
	desiredTables   = []string{"Base"}
	undesiredTables = []string{"_TableList", "About", "PatchClient"}
)

// List of files with a verifiable authenticode signature
// Most other files are signed by an expired certificate, so they have to be ignored :(
var verifiableFiles = []string{
	"Bin\\BugReportBuilderCSR.dll",
	"Bin\\BugReporter.exe",
	"Bin\\WizardGraphicalClient.exe",
}

var makeTableOnce = sync.OnceValue(func() crc32.Table {
	polyReversed := bits.Reverse32(0x4C11DB7)
	return *crc32.MakeTable(polyReversed)
})

func newReverseHasher() reverseHasher {
	return reverseHasher{
		table: makeTableOnce(),
		sum32: 0xFFFFFFFF,
	}
}

type reverseHasher struct {
	table crc32.Table
	sum32 uint32
}

func (h *reverseHasher) Sum32() uint32 {
	return h.sum32 ^ 0xFFFFFFFF
}

func (h *reverseHasher) Write(b []byte) (int, error) {
	h.sum32 = crc32.Update(h.sum32, &h.table, b)
	return len(b), nil
}

func (h *reverseHasher) Reset() {
	h.table = makeTableOnce()
	h.sum32 = 0xFFFFFFFF
}

type patchHandler struct {
	patch.PatchService
	fileListCh chan patch.LatestFileListV2
}

func (p patchHandler) LatestFileListV2(m patch.LatestFileListV2) {
	p.fileListCh <- m
}

type loginHandler struct {
	login.LoginService
	authenRspCh chan login.UserAuthenRsp
}

func (l loginHandler) UserAuthenRsp(m login.UserAuthenRsp) {
	l.authenRspCh <- m
}

type LaunchParams struct {
	Dir              string
	Username         string
	Password         string
	PatchOnly        bool
	FullPatch        bool
	LoginServerAddr  string
	PatchServerAddr  string
	ConcurrencyLimit int
}

func Patch(ctx context.Context, params LaunchParams) error {
	patchClient := newPatchClient(params)
	return patchClient.launch(ctx, params)
}

type patchClient struct {
	LaunchParams
	httpClient *http.Client
	hasherPool *sync.Pool
	fs         afero.Fs
}

func newPatchClient(params LaunchParams) *patchClient {
	hasherPool := sync.Pool{
		New: func() any {
			hasher := newReverseHasher()
			return &hasher
		},
	}

	return &patchClient{
		LaunchParams: params,
		httpClient:   &http.Client{},
		hasherPool:   &hasherPool,
		fs:           afero.NewBasePathFs(afero.NewOsFs(), params.Dir),
	}
}

func (p *patchClient) launch(ctx context.Context, params LaunchParams) error {
	if err := p.checkBaseFiles(ctx); err != nil {
		return err
	}

	slog.Info("All files OK")

	if !params.PatchOnly {
		userID, ck2, err := p.requestCK2Token(ctx, params)
		if err != nil {
			return err
		}

		if err := p.launchGraphicalClient(ctx, userID, ck2); err != nil {
			return err
		}
	}

	return nil
}

type patchFile struct {
	URL    string
	Source string
	Target string
	CRC    uint32
	Size   uint32
	Type   uint32
}

func (p *patchClient) checkBaseFiles(ctx context.Context) error {
	fileList, err := p.latestFileList(ctx)
	if err != nil {
		return err
	}

	fileListBin, err := p.request(ctx, fileList.ListFileURL)
	if err != nil {
		return err
	}
	defer fileListBin.Close()

	dmlTables, err := dml.DecodeTable(fileListBin)
	if err != nil {
		return err
	}

	if err := p.processTables(ctx, fileList.URLPrefix, *dmlTables); err != nil {
		return err
	}

	return nil
}

func (p *patchClient) processTables(ctx context.Context, urlPrefix string, tables []dml.Table) error {
	errGroup, ctx := errgroup.WithContext(ctx)
	errGroup.SetLimit(p.LaunchParams.ConcurrencyLimit)

	for _, table := range tables {
		if !shouldProcessTable(table.Name, p.LaunchParams.FullPatch) {
			continue
		}

		slog.Info("Processing files for table", "table", table.Name)

		for _, record := range table.Records {
			errGroup.Go(func() error {
				return p.processRecord(ctx, urlPrefix, record)
			})
		}
	}

	return errGroup.Wait()
}

func shouldProcessTable(name string, fullPatch bool) bool {
	if !fullPatch && !slices.Contains(desiredTables, name) {
		return false
	}

	if fullPatch && slices.Contains(undesiredTables, name) {
		return false
	}

	return true
}

func (p *patchClient) processRecord(ctx context.Context, urlPrefix string, record dml.Record) error {
	var (
		source   = record["SrcFileName"].(string)
		target   = record["TarFileName"].(string)
		crc      = record["CRC"].(uint32)
		size     = record["Size"].(uint32)
		fileType = record["FileType"].(uint32)
	)
	if target == "" {
		target = source
	}

	// Don't patch dynamic WADs unless in full patch mode, they won't
	// match the expected CRC since they're loaded in segments at runtime
	if fileType == fileTypeDynamicWAD && !p.LaunchParams.FullPatch {
		slog.Info("Skipping dynamic WAD", "file", target)
		return nil
	}

	fileURL, err := url.JoinPath(urlPrefix, source)
	if err != nil {
		return err
	}

	patchFile := patchFile{
		URL:    fileURL,
		Source: filepath.Clean(source),
		Target: filepath.Clean(target),
		CRC:    crc,
		Size:   size,
		Type:   fileType,
	}

	ok, err := p.verifyFileCRC(patchFile)
	if err != nil {
		return fmt.Errorf("error verifying file: %w", err)
	}
	if !ok {
		if err := p.downloadFile(ctx, patchFile); err != nil {
			return fmt.Errorf("error downloading file: %w", err)
		}
	}

	slog.Info("File OK", "crc", patchFile.CRC, "size", patchFile.Size, "path", patchFile.Target)

	return nil
}

func (p *patchClient) launchGraphicalClient(ctx context.Context, userID uint64, ck2 string) error {
	host, port, err := net.SplitHostPort(p.LoginServerAddr)
	if err != nil {
		return err
	}

	args := []string{
		"-L", host, port,
		"-U", ".." + fmt.Sprint(userID),
		ck2,
		p.LaunchParams.Username,
	}

	name := "./WizardGraphicalClient.exe"

	if _, err := p.fs.Open(filepath.Join("Bin", name)); os.IsNotExist(err) {
		return fmt.Errorf("WizardGraphicalClient.exe not found, patching required")
	}

	if launchWithWine {
		slog.Info("Detected platform not Windows, launching with Wine")
		args = append([]string{name}, args...)
		name = "wine"

		if _, err := exec.LookPath(name); err != nil {
			return fmt.Errorf("Wine executable not found in PATH")
		}
	}

	slog.Info("Launching", "cmd", name, "args", args)

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = filepath.Join(p.LaunchParams.Dir, "Bin")

	return cmd.Start()
}

func (p *patchClient) requestCK2Token(ctx context.Context, params LaunchParams) (uint64, string, error) {
	authenRspCh := make(chan login.UserAuthenRsp)

	r := proto.NewMessageRouter()
	login.RegisterLoginService(r, &loginHandler{authenRspCh: authenRspCh})

	ctx, cancel := context.WithTimeoutCause(ctx, 10*time.Second, errTimeoutAuthenRsp)
	defer cancel()

	protoClient, err := proto.Dial(ctx, params.LoginServerAddr, r)
	if err != nil {
		return 0, "", err
	}
	defer protoClient.Close()

	slog.Info("Connected to login server", "server", params.LoginServerAddr)

	var (
		sid               = protoClient.SessionID()
		sessionTimeSecs   = protoClient.SessionTimeSecs()
		sessionTimeMillis = protoClient.SessionTimeMillis()
	)

	var (
		ck1       = crypto.GenerateCK1(params.Password, sid, sessionTimeSecs, sessionTimeMillis)
		authToken = crypto.AuthenToken(params.Username, ck1, sid)
		rec1      = crypto.EncryptRec1(authToken, sid, sessionTimeSecs, sessionTimeMillis)
	)

	loginClient := login.NewLoginClient(protoClient)

	authenV3 := &login.UserAuthenV3{
		Rec1:   string(rec1),
		Locale: "English",
	}
	if err = loginClient.UserAuthenV3(authenV3); err != nil {
		return 0, "", err
	}

	select {
	case rsp := <-authenRspCh:
		if rsp.Error != 0 {
			return 0, "", fmt.Errorf("error code %d during auth (reason: %s)", rsp.Error, rsp.Reason)
		}

		ck2 := crypto.DecryptRec1([]byte(rsp.Rec1), sid, sessionTimeSecs, sessionTimeMillis)
		return rsp.UserID, string(ck2), nil
	case <-ctx.Done():
		return 0, "", ctx.Err()
	}
}

func (p *patchClient) downloadFile(ctx context.Context, patchFile patchFile) error {
	dirname := filepath.Dir(patchFile.Target)
	if err := p.fs.MkdirAll(dirname, 0o755); err != nil {
		return err
	}

	file, err := p.fs.Create(patchFile.Target)
	if err != nil {
		return err
	}
	defer file.Close()

	closeAndRemove := func() {
		file.Close()
		p.fs.Remove(patchFile.Target)
	}

	slog.Info("Downloading file", "url", patchFile.URL)

	resp, err := p.request(ctx, patchFile.URL)
	if err != nil {
		return err
	}
	defer resp.Close()

	hasher := p.hasherPool.Get().(*reverseHasher)
	hasher.Reset()

	defer p.hasherPool.Put(hasher)

	// Tee into hasher to calculate CRC while writing to file
	teeReader := io.TeeReader(resp, hasher)
	if _, err := io.CopyN(file, teeReader, int64(patchFile.Size)); err != nil {
		return err
	}

	actualCRC := hasher.Sum32()
	if actualCRC != patchFile.CRC {
		closeAndRemove()
		return fmt.Errorf("crc mismatch for file %s: expected %d, got %d", patchFile.Target, patchFile.CRC, actualCRC)
	}

	if patchFile.Type == fileTypeExecutable && slices.Contains(verifiableFiles, patchFile.Target) {
		if err := p.verifyFileAuthenticode(patchFile); err != nil {
			closeAndRemove()
			return fmt.Errorf("error verifying file %s: %w", patchFile.Target, err)
		}

		slog.Info("Authenticode verification passed", "path", patchFile.Target)
	}

	return nil
}

func (p *patchClient) verifyFileAuthenticode(patchFile patchFile) error {
	peBytes, err := afero.ReadFile(p.fs, patchFile.Target)
	if err != nil {
		return err
	}

	// Would be preferable to use p.New where it mmaps the given file path
	// but building the full path wouldn't be necessarily confined to the afero.Fs
	pe, err := pe.NewBytes(peBytes, nil)
	if err != nil {
		return err
	}

	if err := pe.Parse(); err != nil {
		return err
	}

	for _, cert := range pe.Certificates.Certificates {
		if !cert.SignatureValid || !cert.Verified {
			return fmt.Errorf("authenticode verification failed")
		}
	}

	return nil
}

func (p *patchClient) verifyFileCRC(patchFile patchFile) (bool, error) {
	filePath := patchFile.Target
	slog.Info("Verifying file", "path", filePath)

	stat, err := p.fs.Stat(filePath)
	switch {
	case os.IsNotExist(err):
		return false, nil
	case stat.IsDir():
		// Remove directory which shouldn't exist
		err = p.fs.RemoveAll(filePath)
		return false, err
	case stat.Size() != int64(patchFile.Size):
		// File exists but size doesn't match
		return false, nil
	case err != nil:
		return false, err
	default:
		// File exists, no error
	}

	file, err := p.fs.Open(filePath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	hasher := p.hasherPool.Get().(*reverseHasher)
	hasher.Reset()

	defer p.hasherPool.Put(hasher)

	if _, err := io.CopyN(hasher, file, int64(patchFile.Size)); err != nil {
		return false, err
	}
	actualCRC := hasher.Sum32()

	return actualCRC == patchFile.CRC, nil
}

func (p *patchClient) latestFileList(ctx context.Context) (*patch.LatestFileListV2, error) {
	fileListCh := make(chan patch.LatestFileListV2)

	r := proto.NewMessageRouter()
	patch.RegisterPatchService(r, &patchHandler{fileListCh: fileListCh})

	ctx, cancel := context.WithTimeoutCause(ctx, 10*time.Second, errTimeoutFileList)
	defer cancel()

	protoClient, err := proto.Dial(ctx, p.LaunchParams.PatchServerAddr, r)
	if err != nil {
		return nil, err
	}
	defer protoClient.Close()

	slog.Info("Connected to patch server", "server", p.LaunchParams.PatchServerAddr)

	c := patch.NewPatchClient(protoClient)
	if err := c.LatestFileListV2(&patch.LatestFileListV2{}); err != nil {
		return nil, err
	}

	select {
	case fileList := <-fileListCh:
		return &fileList, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *patchClient) request(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "KingsIsle Patcher")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code for url %s: %d", url, resp.StatusCode)
	}

	return resp.Body, err
}
