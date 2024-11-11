package main

import (
	"context"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"log/slog"
	"math/bits"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/cedws/w101-client-go/dml"
	crypto "github.com/cedws/w101-client-go/login"
	"github.com/cedws/w101-client-go/proto"
	"github.com/cedws/w101-proto-go/pkg/login"
	"github.com/cedws/w101-proto-go/pkg/patch"
	"golang.org/x/sync/errgroup"
)

const (
	defaultLoginServer = "login.us.wizard101.com:12000"
	defaultPatchServer = "patch.us.wizard101.com:12500"
)

var defaultConcurrencyLimit = runtime.NumCPU()

var (
	errTimeoutAuthenRsp = fmt.Errorf("timed out waiting for authen response")
	errTimeoutFileList  = fmt.Errorf("timed out waiting for latest file list")
)

var (
	desiredTables   = []string{"Base"}
	undesiredTables = []string{"_TableList", "About", "PatchClient"}
)

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

func main() {
	ctx := context.Background()

	var (
		dir                              string
		username, password               string
		loginServerAddr, patchServerAddr string
		patchOnly                        bool
		fullPatch                        bool
	)

	flag.StringVar(&dir, "dir", "Wizard101", "client directory")

	flag.StringVar(&username, "username", "", "login username")
	flag.StringVar(&password, "password", "", "login password")

	flag.StringVar(&loginServerAddr, "login-server", defaultLoginServer, "login server addr")
	flag.StringVar(&patchServerAddr, "patch-server", defaultPatchServer, "patch server addr")

	flag.BoolVar(&patchOnly, "patch-only", false, "only patch files without logging in")
	flag.BoolVar(&fullPatch, "full", false, "patch all game files")

	flag.Parse()

	if !patchOnly && (username == "" || password == "") {
		flag.Usage()
		os.Exit(1)
	}

	params := launchParams{
		Dir:              dir,
		Username:         username,
		Password:         password,
		PatchOnly:        patchOnly,
		FullPatch:        fullPatch,
		LoginServerAddr:  loginServerAddr,
		PatchServerAddr:  patchServerAddr,
		ConcurrencyLimit: defaultConcurrencyLimit,
	}

	patchClient := newPatchClient(params)

	if err := patchClient.launch(ctx, params); err != nil {
		log.Fatal(err)
	}
}

type patchClient struct {
	launchParams
	httpClient *http.Client
	hasherPool *sync.Pool
}

func newPatchClient(params launchParams) *patchClient {
	hasherPool := sync.Pool{
		New: func() any {
			hasher := newReverseHasher()
			return &hasher
		},
	}

	return &patchClient{
		launchParams: params,
		httpClient:   &http.Client{},
		hasherPool:   &hasherPool,
	}
}

type launchParams struct {
	Dir              string
	Username         string
	Password         string
	PatchOnly        bool
	FullPatch        bool
	LoginServerAddr  string
	PatchServerAddr  string
	ConcurrencyLimit int
}

func (p *patchClient) launch(ctx context.Context, params launchParams) error {
	if err := p.checkBaseFiles(ctx); err != nil {
		return err
	}

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
	errGroup.SetLimit(p.launchParams.ConcurrencyLimit)

	for _, table := range tables {
		if !shouldProcessTable(table.Name, p.launchParams.FullPatch) {
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
		source = record["SrcFileName"].(string)
		target = record["TarFileName"].(string)
		crc    = record["CRC"].(uint32)
		size   = record["Size"].(uint32)
	)
	if target == "" {
		target = source
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
	}

	if err := p.checkFile(ctx, patchFile); err != nil {
		return err
	}

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
		p.launchParams.Username,
	}

	name := "./WizardGraphicalClient.exe"
	if launchWithWine {
		slog.Info("Detected platform not windows, launching with wine")
		args = append([]string{name}, args...)
		name = "wine"
	}

	slog.Info("Launching", "bin", name, "args", args)

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = filepath.Join(p.launchParams.Dir, "Bin")

	return cmd.Start()
}

func (p *launchParams) requestCK2Token(ctx context.Context, params launchParams) (uint64, string, error) {
	authenRspCh := make(chan login.UserAuthenRsp)

	r := proto.NewMessageRouter()
	login.RegisterLoginService(r, &loginHandler{authenRspCh: authenRspCh})

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

	ctx, cancel := context.WithTimeoutCause(ctx, 5*time.Second, errTimeoutAuthenRsp)
	defer cancel()

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

func (p *patchClient) checkFile(ctx context.Context, patchFile patchFile) error {
	ok, err := p.verifyFile(patchFile)
	if err != nil {
		return fmt.Errorf("error verifying file: %w", err)
	}
	if ok {
		slog.Info("File OK", "crc", patchFile.CRC, "size", patchFile.Size, "path", patchFile.Target)
		return nil
	}

	dirname := filepath.Dir(patchFile.Target)

	fulldir := filepath.Join(p.launchParams.Dir, dirname)
	if err := os.MkdirAll(fulldir, 0o755); err != nil {
		return err
	}

	slog.Info("Downloading file", "url", patchFile.URL)

	resp, err := p.request(ctx, patchFile.URL)
	if err != nil {
		return err
	}
	defer resp.Close()

	filePath := filepath.Join(p.launchParams.Dir, patchFile.Target)

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := io.Copy(file, resp); err != nil {
		return err
	}

	return nil
}

func (p *patchClient) verifyFile(patchFile patchFile) (bool, error) {
	filePath := filepath.Join(p.launchParams.Dir, patchFile.Target)
	slog.Info("Verifying file", "path", filePath)

	stat, err := os.Stat(filePath)
	switch {
	case os.IsNotExist(err):
		return false, nil
	case stat.Size() != int64(patchFile.Size):
		// File exists but size doesn't match
		return false, nil
	case stat.IsDir():
		// Remove directory which shouldn't exist
		err = os.RemoveAll(filePath)
		return false, err
	case err != nil:
		return false, err
	default:
		// File exists, no error
	}

	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	hasher := p.hasherPool.Get().(*reverseHasher)
	defer p.hasherPool.Put(hasher)

	hasher.Reset()
	if _, err := io.Copy(hasher, file); err != nil {
		return false, err
	}
	actualCRC := hasher.Sum32()

	return actualCRC == patchFile.CRC, nil
}

func (p *patchClient) latestFileList(ctx context.Context) (*patch.LatestFileListV2, error) {
	fileListCh := make(chan patch.LatestFileListV2)

	r := proto.NewMessageRouter()
	patch.RegisterPatchService(r, &patchHandler{fileListCh: fileListCh})

	protoClient, err := proto.Dial(ctx, p.launchParams.PatchServerAddr, r)
	if err != nil {
		return nil, err
	}
	defer protoClient.Close()

	slog.Info("Connected to patch server", "server", p.launchParams.PatchServerAddr)

	c := patch.NewPatchClient(protoClient)
	if err := c.LatestFileListV2(&patch.LatestFileListV2{}); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeoutCause(ctx, 5*time.Second, errTimeoutFileList)
	defer cancel()

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

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return resp.Body, err
}
