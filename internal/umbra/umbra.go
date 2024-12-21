package umbra

import (
	"bufio"
	"context"
	"encoding/binary"
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
	"path"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/cedws/w101-client-go/dml"
	crypto "github.com/cedws/w101-client-go/login"
	"github.com/cedws/w101-client-go/proto"
	"github.com/cedws/w101-proto-go/pkg/login"
	"github.com/cedws/w101-proto-go/pkg/patch"
	"github.com/spf13/afero"
	"golang.org/x/sync/errgroup"
)

const (
	fileTypeExecutable = 4
	fileTypeDynamicWAD = 5
)

const loginServerRetries = 10

var (
	errTimeoutAuthenRsp = fmt.Errorf("timed out waiting for authen response")
	errTimeoutFileList  = fmt.Errorf("timed out waiting for latest file list")
)

var metaTables = []string{"_TableList", "About", "PatchClient"}

// List of files with no authenticode signature
// Most other files are signed by an expired certificate
var unverifiableFiles = []string{
	"Bin/mss64.dll",
	"Bin/mss64midi.dll",
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
	patchClient, err := newPatchClient(params)
	if err != nil {
		return err
	}
	defer patchClient.Close()

	return patchClient.launch(ctx, params)
}

type packagesList struct {
	wc       io.WriteCloser
	packages []string
}

func (l *packagesList) Open(fs afero.Fs) error {
	file, err := fs.OpenFile("LocalPackagesList.txt", os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	l.wc = file

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		l.packages = append(l.packages, scanner.Text())
	}

	for _, pkg := range l.packages {
		slog.Info("Detected package", "package", pkg)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func (l *packagesList) Add(pkg string) {
	if !l.Contains(pkg) {
		l.packages = append(l.packages, pkg)
		l.wc.Write([]byte(pkg + "\n"))
	}
}

func (l *packagesList) Contains(pkg string) bool {
	// Special case: Base table should always be processed
	// but not be present in the packages list
	if pkg == "Base" {
		return true
	}
	return slices.Contains(l.packages, pkg)
}

func (l *packagesList) Close() error {
	return l.wc.Close()
}

type patchClient struct {
	LaunchParams
	httpClient   *http.Client
	hasherPool   *sync.Pool
	fs           afero.Fs
	packagesList packagesList
}

func newPatchClient(params LaunchParams) (*patchClient, error) {
	hasherPool := sync.Pool{
		New: func() any {
			hasher := newReverseHasher()
			return &hasher
		},
	}

	os.MkdirAll(params.Dir, 0o755)

	fs := afero.NewBasePathFs(afero.NewOsFs(), params.Dir)
	fs.MkdirAll("PatchInfo", 0o755)

	var packagesList packagesList
	if err := packagesList.Open(fs); err != nil {
		return nil, fmt.Errorf("error opening packages list: %w", err)
	}

	return &patchClient{
		LaunchParams: params,
		httpClient:   &http.Client{},
		hasherPool:   &hasherPool,
		fs:           fs,
		packagesList: packagesList,
	}, nil
}

func (p *patchClient) Close() error {
	return p.packagesList.Close()
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

	dmlTables, err := p.fileListTables(ctx, fileList)
	if err != nil {
		return err
	}

	if err := p.processTables(ctx, fileList.URLPrefix, *dmlTables); err != nil {
		return err
	}

	return nil
}

func (p *patchClient) fileListTables(ctx context.Context, fileList *patch.LatestFileListV2) (*[]dml.Table, error) {
	fileListBin, err := p.request(ctx, fileList.ListFileURL)
	if err != nil {
		return nil, err
	}
	defer fileListBin.Close()

	cacheFile, err := createLatestFileList(p.fs)
	if err != nil {
		return nil, err
	}
	defer cacheFile.Close()

	cacheTee := io.TeeReader(fileListBin, cacheFile)

	return dml.DecodeTable(cacheTee)
}

func createLatestFileList(fs afero.Fs) (io.WriteCloser, error) {
	return fs.Create("PatchInfo/LatestFileList.bin")
}

func createCRCFile(fs afero.Fs, name string) (io.WriteCloser, error) {
	return fs.Create(fmt.Sprintf("PatchInfo/CRC_%v.dat", name))
}

func (p *patchClient) writeCRCRecord(w io.Writer, record dml.Record) error {
	hasher := p.hasherPool.Get().(*reverseHasher)
	hasher.Reset()

	defer p.hasherPool.Put(hasher)

	var (
		source = record["SrcFileName"].(string)
		crc    = record["CRC"].(uint32)
		size   = record["Size"].(uint32)
	)

	hasher.Write([]byte(source))

	var (
		fileNameCRC = hasher.Sum32()
		timestamp   = time.Now().UnixMilli()
	)

	var bytes []byte
	bytes = binary.LittleEndian.AppendUint32(bytes, fileNameCRC)
	bytes = binary.LittleEndian.AppendUint32(bytes, size)
	bytes = binary.LittleEndian.AppendUint32(bytes, crc)
	bytes = binary.LittleEndian.AppendUint32(bytes, 0)
	bytes = binary.LittleEndian.AppendUint64(bytes, uint64(timestamp))

	if len(bytes) != 24 {
		panic("expected 24 bytes for crc record")
	}

	_, err := w.Write(bytes)
	return err
}

func (p *patchClient) processTables(ctx context.Context, urlPrefix string, tables []dml.Table) error {
	errGroup, ctx := errgroup.WithContext(ctx)
	errGroup.SetLimit(p.LaunchParams.ConcurrencyLimit)

	for _, table := range tables {
		if !p.shouldProcessTable(table.Name) {
			continue
		}

		crcFile, err := createCRCFile(p.fs, table.Name)
		if err != nil {
			return err
		}
		defer crcFile.Close()

		slog.Info("Processing files for table", "table", table.Name)

		for _, record := range table.Records {
			errGroup.Go(func() error {
				if err := p.processRecord(ctx, urlPrefix, record); err != nil {
					return fmt.Errorf("error processing record: %w", err)
				}

				if err := p.writeCRCRecord(crcFile, record); err != nil {
					return fmt.Errorf("error writing CRC record: %w", err)
				}

				return nil
			})
		}

		// Adding it to the packages list here is a bit premature but it won't hurt
		p.packagesList.Add(table.Name)
	}

	return errGroup.Wait()
}

func (p *patchClient) shouldProcessTable(name string) bool {
	// Skip meta tables
	if slices.Contains(metaTables, name) {
		return false
	}

	// User requested full patch, process all tables
	if p.LaunchParams.FullPatch {
		return true
	}

	// Package has been downloaded, verify it
	if p.packagesList.Contains(name) {
		return true
	}

	return false
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
		Source: path.Clean(source),
		Target: path.Clean(target),
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
	login.RegisterLoginService(&r, &loginHandler{authenRspCh: authenRspCh})

	ctx, cancel := context.WithTimeoutCause(ctx, 10*time.Second, errTimeoutAuthenRsp)
	defer cancel()

	var (
		protoClient *proto.Client
		err         error
	)

	// Temporary workaround for KI login server issues
	// For some reason they're dropping connections every so often
	for range loginServerRetries {
		protoClient, err = proto.Dial(ctx, params.LoginServerAddr, &r)
		if err == nil {
			break
		}
	}
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

	if patchFile.Type == fileTypeExecutable && !slices.Contains(unverifiableFiles, patchFile.Target) {
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

	return verifyAuthenticode(peBytes)
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
	patch.RegisterPatchService(&r, &patchHandler{fileListCh: fileListCh})

	ctx, cancel := context.WithTimeoutCause(ctx, 10*time.Second, errTimeoutFileList)
	defer cancel()

	protoClient, err := proto.Dial(ctx, p.LaunchParams.PatchServerAddr, &r)
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
