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
	"time"

	"github.com/cedws/w101-client-go/dml"
	crypto "github.com/cedws/w101-client-go/login"
	"github.com/cedws/w101-client-go/proto"
	"github.com/cedws/w101-proto-go/pkg/login"
	"github.com/cedws/w101-proto-go/pkg/patch"
)

const (
	defaultLoginServer = "login.us.wizard101.com:12000"
	defaultPatchServer = "patch.us.wizard101.com:12500"
)

var (
	errTimeoutAuthenRsp = fmt.Errorf("timed out waiting for authen response")
	errTimeoutFileList  = fmt.Errorf("timed out waiting for latest file list")
)

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

	params := LaunchParams{
		Dir:             dir,
		Username:        username,
		Password:        password,
		PatchOnly:       patchOnly,
		LoginServerAddr: loginServerAddr,
		PatchServerAddr: patchServerAddr,
	}

	if err := launch(ctx, params); err != nil {
		log.Fatal(err)
	}
}

type LaunchParams struct {
	Dir             string
	Username        string
	Password        string
	PatchOnly       bool
	LoginServerAddr string
	PatchServerAddr string
}

func launch(ctx context.Context, params LaunchParams) error {
	fileList, err := latestFileList(ctx, params)
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

	for _, table := range *dmlTables {
		if table.Name != "Base" {
			continue
		}

		slog.Info("Downloading files for table", "table", table.Name)

		for _, record := range table.Records {
			if err := download(ctx, fileList.URLPrefix, record, params); err != nil {
				return err
			}
		}
	}

	if !params.PatchOnly {
		userID, ck2, err := requestCK2Token(ctx, params)
		if err != nil {
			return err
		}

		if err := launchGraphicalClient(ctx, userID, ck2, params); err != nil {
			return err
		}
	}

	return nil
}

func launchGraphicalClient(ctx context.Context, userID uint64, ck2 string, params LaunchParams) error {
	host, port, err := net.SplitHostPort(defaultLoginServer)
	if err != nil {
		return err
	}

	args := []string{
		"-L", host, port,
		"-U", ".." + fmt.Sprint(userID),
		string(ck2),
		params.Username,
	}
	slog.Info("Launching WizardGraphicalClient.exe", "args", args)

	cmd := exec.CommandContext(ctx, "./WizardGraphicalClient.exe", args...)
	cmd.Dir = filepath.Join(params.Dir, "Bin")

	return cmd.Start()
}

func requestCK2Token(ctx context.Context, params LaunchParams) (uint64, string, error) {
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

func download(ctx context.Context, prefix string, record dml.Record, params LaunchParams) error {
	srcFileName := record["SrcFileName"].(string)
	tarFileName := record["TarFileName"].(string)

	if tarFileName == "" {
		tarFileName = srcFileName
	}

	dirname := filepath.Dir(tarFileName)

	fulldir := filepath.Join(params.Dir, dirname)
	if err := os.MkdirAll(fulldir, 0755); err != nil {
		return err
	}

	fileURL, err := url.JoinPath(prefix, srcFileName)
	if err != nil {
		return err
	}

	slog.Info("Downloading file", "url", fileURL)

	resp, err := request(ctx, fileURL)
	if err != nil {
		return err
	}
	defer resp.Close()

	file, err := os.Create(filepath.Join(params.Dir, tarFileName))
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := io.Copy(file, resp); err != nil {
		return err
	}

	return nil
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

func latestFileList(ctx context.Context, params LaunchParams) (*patch.LatestFileListV2, error) {
	fileListCh := make(chan patch.LatestFileListV2)

	r := proto.NewMessageRouter()
	patch.RegisterPatchService(r, &patchHandler{fileListCh: fileListCh})

	protoClient, err := proto.Dial(ctx, params.PatchServerAddr, r)
	if err != nil {
		return nil, err
	}
	defer protoClient.Close()

	slog.Info("Connected to patch server", "server", params.PatchServerAddr)

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
