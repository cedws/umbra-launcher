package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/cedws/w101-client-go/dml"
	crypto "github.com/cedws/w101-client-go/login"
	"github.com/cedws/w101-client-go/proto"
	"github.com/cedws/w101-proto-go/pkg/login"
	"github.com/cedws/w101-proto-go/pkg/patch"
	"github.com/snksoft/crc"
)

const (
	defaultLoginServer = "login.us.wizard101.com:12000"
	defaultPatchServer = "patch.us.wizard101.com:12500"
)

var (
	errTimeoutAuthenRsp = fmt.Errorf("timed out waiting for authen response")
	errTimeoutFileList  = fmt.Errorf("timed out waiting for latest file list")
)

var makeHasherOnce = sync.OnceValue(func() fileHasher {
	hash := *crc.NewHash(&crc.Parameters{
		Width:      32,
		Polynomial: 0x4C11DB7,
		ReflectIn:  true,
		ReflectOut: true,
		Init:       0,
		FinalXor:   0,
	})

	return fileHasher{hash}
})

type fileHasher struct {
	crc.Hash
}

func (f *fileHasher) Write(b []byte) (int, error) {
	f.Hash.Update(b)
	return len(b), nil
}

func (f *fileHasher) CRC32() uint32 {
	return f.Hash.CRC32()
}

func (f *fileHasher) Reset() {
	f.Hash.Reset()
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
	)

	flag.StringVar(&dir, "dir", "Wizard101", "client directory")

	flag.StringVar(&username, "username", "", "login username")
	flag.StringVar(&password, "password", "", "login password")

	flag.StringVar(&loginServerAddr, "login-server", defaultLoginServer, "login server addr")
	flag.StringVar(&patchServerAddr, "patch-server", defaultPatchServer, "patch server addr")

	flag.BoolVar(&patchOnly, "patch-only", false, "only patch files without logging in")

	flag.Parse()

	if !patchOnly && (username == "" || password == "") {
		flag.Usage()
		os.Exit(1)
	}

	params := launchParams{
		Dir:             dir,
		Username:        username,
		Password:        password,
		PatchOnly:       patchOnly,
		LoginServerAddr: loginServerAddr,
		PatchServerAddr: patchServerAddr,
	}

	patchClient := newPatchClient(params)

	if err := patchClient.launch(ctx, params); err != nil {
		log.Fatal(err)
	}
}

type patchClient struct {
	launchParams
	hasher *fileHasher
}

func newPatchClient(params launchParams) *patchClient {
	hasher := makeHasherOnce()

	return &patchClient{
		launchParams: params,
		hasher:       &hasher,
	}
}

type launchParams struct {
	Dir             string
	Username        string
	Password        string
	PatchOnly       bool
	LoginServerAddr string
	PatchServerAddr string
}

func (p *patchClient) launch(ctx context.Context, params launchParams) error {
	if err := p.downloadBaseFiles(ctx); err != nil {
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
}

func (p *patchClient) downloadBaseFiles(ctx context.Context) error {
	fileList, err := p.latestFileList(ctx)
	if err != nil {
		return err
	}

	fileListBin, err := request(ctx, fileList.ListFileURL)
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
	for _, table := range tables {
		if table.Name == "Base" {
			slog.Info("Processing files for table", "table", table.Name)

			for _, record := range table.Records {
				if err := p.processRecord(ctx, urlPrefix, record); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (p *patchClient) processRecord(ctx context.Context, urlPrefix string, record dml.Record) error {
	source := record["SrcFileName"].(string)
	target := record["TarFileName"].(string)
	crc := record["CRC"].(uint32)

	if target == "" {
		target = source
	}

	fileURL, err := url.JoinPath(urlPrefix, source)
	if err != nil {
		return err
	}

	source = filepath.Clean(source)
	target = filepath.Clean(target)

	patchFile := patchFile{
		URL:    fileURL,
		Source: source,
		Target: target,
		CRC:    crc,
	}

	if err := p.download(ctx, patchFile); err != nil {
		return err
	}

	return nil
}

func (p *patchClient) launchGraphicalClient(ctx context.Context, userID uint64, ck2 string) error {
	host, port, err := net.SplitHostPort(defaultLoginServer)
	if err != nil {
		return err
	}

	args := []string{
		"-L", host, port,
		"-U", ".." + fmt.Sprint(userID),
		string(ck2),
		p.launchParams.Username,
	}
	slog.Info("Launching WizardGraphicalClient.exe", "args", args)

	cmd := exec.CommandContext(ctx, "./WizardGraphicalClient.exe", args...)
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
		ck2 := crypto.DecryptRec1([]byte(rsp.Rec1), sid, sessionTimeSecs, sessionTimeMillis)
		return rsp.UserID, string(ck2), nil
	case <-ctx.Done():
		return 0, "", ctx.Err()
	}
}

func (p *patchClient) download(ctx context.Context, patchFile patchFile) error {
	ok, err := p.verifyFile(patchFile)
	if err != nil {
		return fmt.Errorf("error verifying file: %w", err)
	}
	if ok {
		slog.Info("File OK", "crc", patchFile.CRC, "path", patchFile.Target)
		return nil
	}

	dirname := filepath.Dir(patchFile.Target)

	fulldir := filepath.Join(p.launchParams.Dir, dirname)
	if err := os.MkdirAll(fulldir, 0755); err != nil {
		return err
	}

	slog.Info("Downloading file", "url", patchFile.URL)

	resp, err := request(ctx, patchFile.URL)
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
	case err != nil:
		return false, err
	case stat.IsDir():
		return false, nil
	default:
		// File exists, no error
	}

	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	p.hasher.Reset()
	if _, err := io.Copy(p.hasher, file); err != nil {
		return false, err
	}
	actualCRC := p.hasher.CRC32()

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

func request(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return resp.Body, err
}
