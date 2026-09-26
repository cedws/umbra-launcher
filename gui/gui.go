package gui

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"github.com/cedws/umbra-launcher/internal/umbra"
	"go.hasen.dev/generic"
	. "go.hasen.dev/shirei"
	app "go.hasen.dev/shirei/app"
	. "go.hasen.dev/shirei/widgets"
)

type model struct {
	dir         string
	username    string
	password    string
	loginServer string
	patchServer string
	patchOnly   bool
	fullPatch   bool
	running     bool
	started     bool
	status      string
	err         string
	cancel      context.CancelFunc
	logs        *TextRing
	logHandler  *logHandler
	persisted   savedSettings
	persistMu   sync.Mutex
}

type logHandler struct {
	attrs  []slog.Attr
	groups []string
	ring   *TextRing
}

type activityState struct {
	ring        *TextRing
	lastCount   int
	scrollY     float32
	maxScroll   float32
	prevScrollY float32
	pinned      bool
}

func Run() {
	_, wineErr := exec.LookPath("wine")
	wineMissing := runtime.GOOS != "windows" && wineErr != nil
	settings := loadSettings()
	m := &model{
		dir:         settings.Dir,
		username:    settings.Username,
		loginServer: settings.LoginServer,
		patchServer: settings.PatchServer,
		patchOnly:   settings.PatchOnly,
		fullPatch:   settings.FullPatch,
		status:      "Ready to patch",
		logs:        NewTextRing(1 << 20),
		persisted:   settings,
	}
	logger := &logHandler{ring: m.logs}
	m.logHandler = logger
	slog.SetDefault(slog.New(logger))
	generic.AddExitCleanup(m.saveSettings)
	app.SetupWindow("Umbra Launcher", 580, 680)
	if wineMissing {
		ToastWithAccent(SymInfo, "Wine not found",
			"Install Wine and make sure `wine` is on PATH to launch the game.",
			ToastBackgroundWarning)
	}
	app.Run(m.view)
}

func (m *model) view() {
	SetLightColorScheme(LightColorScheme())
	SetDarkColorScheme(DarkColorScheme())
	SetDarkMode(true)
	ModAttrs(UseSurface(SurfaceCanvas))
	Container(Attrs(Viewport, Pad(20), Gap(14)), func() {
		Container(Attrs(Expand, UseSurface(SurfacePanel), Pad(16),
			Gap(11), Corners(8), BorderWidth(1)), func() {
			Label("CLIENT SETTINGS", FontSize(11),
				FontWeight(WeightBold),
				TextColorVec(CurrentColorScheme.List.Muted))
			directoryField("Install location", &m.dir)
			field("Patch server", &m.patchServer, 480, false)
			field("Login server", &m.loginServer, 480, false)
			Container(Attrs(Row, Gap(16), CrossMid), func() {
				CheckBox(&m.patchOnly, "Patch only")
				CheckBox(&m.fullPatch, "Download all files")
			})
			if !m.patchOnly {
				Container(Attrs(Expand, UseSurface(SurfaceCanvas), Pad(12),
					Gap(10), Corners(6)), func() {
					Label("Wizard101 Account", FontSize(10),
						FontWeight(WeightBold),
						TextColorVec(CurrentColorScheme.List.Muted))
					field("Username", &m.username, 480, false)
					field("Password", &m.password, 480, true)
				})
			}
		})

		Container(Attrs(Row, CrossMid, Gap(12)), func() {
			if m.running {
				if Button(SymICross, "Cancel") && m.cancel != nil {
					m.cancel()
				}
			} else {
				NextButtonType(ButtonPrimary)
				if Button(SymPlay, "Patch and launch") {
					m.start()
				}
			}
			Label(m.status, FontSize(12),
				TextColorVec(CurrentColorScheme.List.Muted))
		})
		if m.err != "" {
			Label(m.err, FontSize(12),
				TextColorVec(CurrentColorScheme.List.Error))
		}

		if m.started {
			Container(Attrs(Grow(1), Expand, Gap(7)), func() {
				Label("ACTIVITY", FontSize(11), FontWeight(WeightBold),
					TextColorVec(CurrentColorScheme.List.Muted))
				Container(Attrs(Grow(1), Expand, UseSurface(SurfacePanel),
					Pad(8), Corners(8)), func() {
					style := TextStyle(
						FontSize(12),
						TextColorVec(CurrentColorScheme.Surfaces.Panel.Text),
					)
					activityView(m.logs, style)
				})
			})
		}
	})
	m.persistIfChanged()
}

func activityView(ring *TextRing, style TextStyleAttrs) {
	Container(Attrs(Viewport, NoAnimate), func() {
		state := Use[activityState]("activity-view")
		if state.ring != ring {
			*state = activityState{ring: ring, pinned: true}
		}
		count := ring.Len()
		wheelUp := IsHovered() && GetFrameInput().Scroll[1] < 0
		if state.pinned && count > 0 && !wheelUp &&
			(count != state.lastCount ||
				state.scrollY+0.5 < state.maxScroll) {
			VirtualListView_ScrollToEnd(ring, 0)
		}

		vpad := style.FontSize / 4
		VirtualListViewExt(ring, VirtualListAttrs{
			ItemCount: count,
			ItemKey:   func(index int) any { return ring.LineID(index) },
			ItemHeight: func(int, float32) float32 {
				return max(style.FontSize, float32(1)) + 2*vpad
			},
			ItemView: func(index int, width float32) {
				Container(Attrs(Pad2(vpad, 0), Expand, Grow(1),
					MaxWidth(width)), func() {
					shaped := ShapeTextMax(
						ring.Line(index), style, 100000,
					)
					ShapedTextLayoutStyled(shaped, style, 0, 0,
						CurrentColorScheme.Log.Selection)
				})
			},
			OutScrollOffset:    &state.scrollY,
			OutMaxScrollOffset: &state.maxScroll,
		})

		if state.scrollY < state.prevScrollY-0.5 &&
			state.scrollY+0.5 < state.maxScroll {
			state.pinned = false
		} else if !state.pinned {
			margin := max(style.FontSize*2, float32(8))
			if state.scrollY+margin >= state.maxScroll {
				state.pinned = true
			}
		}
		state.prevScrollY = state.scrollY
		state.lastCount = count
	})
}

func field(label string, value *string, width float32, masked bool) {
	Container(Attrs(Gap(4)), func() {
		Label(label, FontSize(12),
			TextColorVec(CurrentColorScheme.List.Muted))
		attrs := DefaultTextInputAttrs()
		attrs.MinWidth = width
		attrs.Masked = masked
		TextInputExt(value, attrs)
	})
}

func directoryField(label string, value *string) {
	Container(Attrs(Gap(4)), func() {
		Label(label, FontSize(12),
			TextColorVec(CurrentColorScheme.List.Muted))
		DirectoryBrowseExt(value, FileBrowserAttrs{Dirs: true, MinWidth: 400})
	})
}

func (m *model) start() {
	if strings.TrimSpace(m.dir) == "" {
		m.err = "Choose a client folder."
		return
	}
	if !m.patchOnly && (m.username == "" || m.password == "") {
		m.err = "Enter your username and password to log in."
		return
	}
	m.persistIfChanged()
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.running = true
	m.started = true
	m.err = ""
	m.status = "Patching client…"
	m.logs = NewTextRing(1 << 20)
	m.logHandler.ring = m.logs
	params := umbra.LaunchParams{
		Dir:              m.dir,
		Username:         m.username,
		Password:         m.password,
		LoginServerAddr:  m.loginServer,
		PatchServerAddr:  m.patchServer,
		PatchOnly:        m.patchOnly,
		FullPatch:        m.fullPatch,
		ConcurrencyLimit: runtime.NumCPU(),
	}
	go func() {
		err := umbra.Patch(ctx, params)
		if err == nil && !params.PatchOnly {
			app.Quit()
			return
		}
		WithFrameLock(func() {
			m.running = false
			m.cancel = nil
			if err != nil {
				if ctx.Err() != nil {
					m.status = "Cancelled"
				} else {
					m.status = "Patch failed"
					m.err = err.Error()
				}
			} else {
				m.status = "Complete"
			}
		})
		RequestNextFrame()
	}()
}

func (m *model) saveSettings() {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	if err := writeSettings(m.persisted); err != nil {
		fmt.Fprintln(os.Stderr, "Could not save launcher settings:", err)
	}
}

func (m *model) persistIfChanged() {
	settings := m.currentSettings()
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	if settings == m.persisted {
		return
	}
	if err := writeSettings(settings); err != nil {
		fmt.Fprintln(os.Stderr, "Could not save launcher settings:", err)
	}
	m.persisted = settings
}

func (m *model) currentSettings() savedSettings {
	return savedSettings{
		Version:     settingsVersion,
		Dir:         m.dir,
		Username:    m.username,
		LoginServer: m.loginServer,
		PatchServer: m.patchServer,
		PatchOnly:   m.patchOnly,
		FullPatch:   m.fullPatch,
	}
}

func (h *logHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *logHandler) Handle(_ context.Context, record slog.Record) error {
	var line strings.Builder
	line.WriteString(record.Level.String())
	line.WriteString("  ")
	line.WriteString(record.Message)
	attrs := append([]slog.Attr(nil), h.attrs...)
	record.Attrs(func(attr slog.Attr) bool {
		attrs = append(attrs, attr)
		return true
	})
	for _, attr := range attrs {
		line.WriteString("  ")
		if len(h.groups) > 0 {
			line.WriteString(strings.Join(h.groups, "."))
			line.WriteByte('.')
		}
		line.WriteString(attr.Key)
		line.WriteByte('=')
		line.WriteString(fmt.Sprint(attr.Value.Any()))
	}
	entry := strings.NewReplacer("\r", " ", "\n", " ").Replace(line.String())
	WithFrameLock(func() { h.ring.AppendLine(entry) })
	RequestNextFrame()
	return nil
}

func (h *logHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	copy := *h
	copy.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &copy
}

func (h *logHandler) WithGroup(name string) slog.Handler {
	copy := *h
	copy.groups = append(append([]string(nil), h.groups...), name)
	return &copy
}
