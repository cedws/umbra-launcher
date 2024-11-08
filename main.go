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

var (
	errTimeoutAuthenRsp = fmt.Errorf("timed out waiting for authen response")
	errTimeoutFileList  = fmt.Errorf("timed out waiting for latest file list")
)

const (
	loginServer = "login.us.wizard101.com:12000"
	patchServer = "patch.us.wizard101.com:12500"
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

	var username, password string

	flag.StringVar(&username, "username", "", "login username")
	flag.StringVar(&password, "password", "", "login password")

	flag.Parse()

	if username == "" || password == "" {
		flag.Usage()
		os.Exit(1)
	}

	if err := startPatch(ctx, username, password); err != nil {
		log.Fatal(err)
	}
}

func startPatch(ctx context.Context, username, password string) error {
	userID, ck2, err := requestCK2Token(ctx, username, password)
	if err != nil {
		return err
	}

	fileList, err := latestFileList(ctx)
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
			if err := download(ctx, fileList.URLPrefix, record); err != nil {
				return err
			}
		}
	}

	if err := launch(ctx, userID, username, ck2); err != nil {
		return err
	}

	return nil
}

func launch(ctx context.Context, userID uint64, username, ck2 string) error {
	host, port, err := net.SplitHostPort(loginServer)
	if err != nil {
		return err
	}

	args := []string{
		"-L", host, port,
		"-U", ".." + fmt.Sprint(userID),
		string(ck2),
		username,
	}
	slog.Info("Launching WizardGraphicalClient.exe", "args", args)

	cmd := exec.CommandContext(ctx, "./WizardGraphicalClient.exe", args...)
	cmd.Dir = "patch/Bin"

	return cmd.Start()
}

func requestCK2Token(ctx context.Context, username, password string) (uint64, string, error) {
	authenRspCh := make(chan login.UserAuthenRsp)

	r := proto.NewMessageRouter()
	login.RegisterLoginService(r, &loginHandler{authenRspCh: authenRspCh})

	slog.Info("Connecting to login server", "server", loginServer)

	protoClient, err := proto.Dial(ctx, loginServer, r)
	if err != nil {
		return 0, "", err
	}
	defer protoClient.Close()

	var (
		sid               = protoClient.SessionID()
		sessionTimeSecs   = protoClient.SessionTimeSecs()
		sessionTimeMillis = protoClient.SessionTimeMillis()
	)

	var (
		ck1       = crypto.GenerateCK1(password, sid, sessionTimeSecs, sessionTimeMillis)
		authToken = crypto.AuthenToken(username, ck1, sid)
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

func download(ctx context.Context, prefix string, record dml.Record) error {
	srcFileName := record["SrcFileName"].(string)
	tarFileName := record["TarFileName"].(string)

	if tarFileName == "" {
		tarFileName = srcFileName
	}

	dirname := filepath.Dir(tarFileName)

	fulldir := filepath.Join("patch", dirname)
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

	file, err := os.Create(filepath.Join("patch", tarFileName))
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

func latestFileList(ctx context.Context) (*patch.LatestFileListV2, error) {
	fileListCh := make(chan patch.LatestFileListV2)

	r := proto.NewMessageRouter()
	patch.RegisterPatchService(r, &patchHandler{fileListCh: fileListCh})

	client, err := proto.Dial(ctx, patchServer, r)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	slog.Info("Connected to patch server", "server", patchServer)

	c := patch.NewPatchClient(client)
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
