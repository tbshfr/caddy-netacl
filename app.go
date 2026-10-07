package netacl

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(new(App))
}

// App holds the databases, groups and background loops shared by all
// handlers and matchers. Without a netacl global option it starts empty, so
// IP-only policies need no global configuration.
type App struct {
	// Only opened if a rule uses country or continent selectors.
	DBCountry string `json:"db_country,omitempty"`
	// Only opened if a rule uses asn selectors.
	DBASN string `json:"db_asn,omitempty"`
	// Download DB-IP Lite into Caddy's data directory and keep it current.
	// Applies to each database slot that is not set explicitly.
	AutoUpdate bool `json:"auto_update,omitempty"`
	// Zero disables reloading; otherwise at least one second.
	ReloadInterval caddy.Duration      `json:"reload_interval,omitempty"`
	Groups         map[string]Selector `json:"groups,omitempty"`

	ctx     caddy.Context
	logger  *zap.Logger
	groups  *groupSet
	metrics *metrics

	mu      sync.Mutex
	country *dbHolder
	asn     *dbHolder
	ipLists map[string]*ipList
	managed map[dbKind]bool

	lookupErrLog logThrottle

	// Overridable in tests.
	httpClient  *http.Client
	dbipURL     string
	now         func() time.Time
	updateEvery time.Duration

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// A shorter interval would mostly spend CPU on stat calls.
const minReloadInterval = time.Second

func (*App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "netacl",
		New: func() caddy.Module { return new(App) },
	}
}

func (a *App) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	a.logger = ctx.Logger()
	a.ipLists = make(map[string]*ipList)
	a.managed = make(map[dbKind]bool)
	a.metrics = newMetrics()
	if err := a.metrics.register(ctx.GetMetricsRegistry()); err != nil {
		return fmt.Errorf("registering metrics: %w", err)
	}
	if a.ReloadInterval < 0 {
		return fmt.Errorf("reload_interval must not be negative")
	}
	if a.ReloadInterval != 0 && time.Duration(a.ReloadInterval) < minReloadInterval {
		return fmt.Errorf("reload_interval %s: must be 0 (off) or at least %s", time.Duration(a.ReloadInterval), minReloadInterval)
	}
	a.lookupErrLog.every = time.Minute
	if a.httpClient == nil {
		a.httpClient = &http.Client{Timeout: 10 * time.Minute}
	}
	if a.dbipURL == "" {
		a.dbipURL = dbipBaseURL
	}
	if a.now == nil {
		a.now = time.Now
	}
	if a.updateEvery == 0 {
		// Each release appears a few hours into the month; checking a few
		// times a day picks it up the same day without hammering DB-IP.
		a.updateEvery = 6 * time.Hour
	}

	repl := caddy.NewReplacer()
	a.DBCountry = repl.ReplaceKnown(a.DBCountry, "")
	a.DBASN = repl.ReplaceKnown(a.DBASN, "")
	if a.AutoUpdate {
		dir := filepath.Join(caddy.AppDataDir(), "netacl")
		if a.DBCountry == "" {
			a.DBCountry = filepath.Join(dir, dbipFileName(dbCountry))
			a.managed[dbCountry] = true
		}
		if a.DBASN == "" {
			a.DBASN = filepath.Join(dir, dbipFileName(dbASN))
			a.managed[dbASN] = true
		}
		if len(a.managed) == 0 {
			a.logger.Warn("auto_update has no effect: db_country and db_asn are both set explicitly")
		}
	}

	gs, err := resolveGroups(a.Groups)
	if err != nil {
		return err
	}
	a.groups = gs
	// Loaded here so a bad ip_file fails the config even if its group is
	// unused.
	names := make([]string, 0, len(gs.flat))
	for name := range gs.flat {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		for _, path := range gs.flat[name].ipFiles {
			if _, err := a.ipList(path); err != nil {
				return fmt.Errorf("group %q: %w", name, err)
			}
		}
	}
	return nil
}

func (a *App) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	if a.ReloadInterval > 0 {
		a.wg.Go(func() { a.reloadLoop(ctx, time.Duration(a.ReloadInterval)) })
	}
	if len(a.managed) > 0 {
		a.wg.Go(func() { a.updateLoop(ctx) })
	}
	return nil
}

// Caddy creates a new app on every config reload, so the old loops must not
// outlive their config.
func (a *App) Stop() error {
	if a.cancel != nil {
		a.cancel()
		a.wg.Wait()
		a.cancel = nil
	}
	return nil
}

// The lock is not held while the database is loaded or downloaded, which can
// take minutes.
func (a *App) database(kind dbKind) (*dbHolder, error) {
	a.mu.Lock()
	slot, path := &a.country, a.DBCountry
	if kind == dbASN {
		slot, path = &a.asn, a.DBASN
	}
	holder := *slot
	a.mu.Unlock()
	if holder != nil {
		return holder, nil
	}
	if path == "" {
		return nil, fmt.Errorf("a rule needs the %s database, but %s is not configured in the global netacl options (or enable auto_update)", kind, kind.option())
	}

	h, err := a.openDB(kind, path)
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if *slot != nil {
		return *slot, nil
	}
	holder = &dbHolder{kind: kind, path: path}
	holder.cur.Store(h)
	*slot = holder
	a.metrics.buildTime.WithLabelValues(kind.String()).Set(float64(h.built.Unix()))
	return holder, nil
}

// openDB loads the database at path. A managed database that is missing or
// unusable, for example truncated by a full disk, is downloaded again, so it
// cannot keep the config from loading.
func (a *App) openDB(kind dbKind, path string) (*dbHandle, error) {
	h, err := loadDB(kind, path)
	if err == nil {
		a.logger.Info("loaded database",
			zap.String("db", kind.String()),
			zap.String("path", path),
			zap.String("type", h.dbType),
			zap.Time("built", h.built))
		return h, nil
	}
	if !a.managed[kind] {
		return nil, err
	}
	if !errors.Is(err, fs.ErrNotExist) {
		a.logger.Warn("stored database is unusable; downloading a fresh copy",
			zap.String("db", kind.String()), zap.String("path", path), zap.Error(err))
	}

	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Minute)
	h, err = fetchLatestDBIP(ctx, a.httpClient, a.dbipURL, kind, a.now(), path)
	cancel()
	if err != nil {
		a.metrics.downloads.WithLabelValues(kind.String(), "error").Inc()
		return nil, fmt.Errorf("auto_update: downloading the %s database: %w", kind, err)
	}
	a.metrics.downloads.WithLabelValues(kind.String(), "success").Inc()
	a.logDownload(kind, path, h)
	return h, nil
}

func (a *App) logDownload(kind dbKind, path string, h *dbHandle) {
	a.logger.Info("downloaded DB-IP Lite database",
		zap.String("db", kind.String()),
		zap.String("path", path),
		zap.Time("built", h.built),
		zap.String("license", "CC BY 4.0, attribution required: https://db-ip.com"))
}

func (a *App) ipList(path string) (*ipList, error) {
	path = caddy.NewReplacer().ReplaceKnown(path, "")
	key, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("ip_file %s: %w", path, err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if l, ok := a.ipLists[key]; ok {
		return l, nil
	}
	d, err := loadIPList(path)
	if err != nil {
		return nil, err
	}
	l := &ipList{path: path}
	l.cur.Store(d)
	a.ipLists[key] = l
	a.logger.Info("loaded ip_file", zap.String("path", path), zap.Int("entries", d.count))
	return l, nil
}

func (a *App) geoSource() geoSource {
	a.mu.Lock()
	defer a.mu.Unlock()
	return geoDBs{country: a.country, asn: a.asn}
}

func (a *App) updateLoop(ctx context.Context) {
	fetched := make(map[dbKind]time.Time)
	for {
		a.updateOnce(ctx, fetched)
		select {
		case <-ctx.Done():
			return
		case <-time.After(a.updateEvery):
		}
	}
}

// updateOnce downloads a new release for every managed database that is in
// use and older than the current month. fetched records the release each
// download installed, so a file whose build date lags its release month is
// not downloaded again on every check.
func (a *App) updateOnce(ctx context.Context, fetched map[dbKind]time.Time) {
	month := releaseMonth(a.now())
	for _, kind := range []dbKind{dbCountry, dbASN} {
		if !a.managed[kind] {
			continue
		}
		a.mu.Lock()
		h := a.country
		if kind == dbASN {
			h = a.asn
		}
		a.mu.Unlock()
		if h == nil || fetched[kind].Equal(month) || !releaseMonth(h.cur.Load().built).Before(month) {
			continue
		}

		next, err := fetchDBIP(ctx, a.httpClient, a.dbipURL, kind, month, h.path)
		switch {
		case ctx.Err() != nil:
			return
		case errors.Is(err, errNotPublished):
			a.logger.Debug("new DB-IP Lite release not published yet",
				zap.String("db", kind.String()), zap.String("month", month.Format("2006-01")))
			continue
		case err != nil:
			a.metrics.downloads.WithLabelValues(kind.String(), "error").Inc()
			a.logger.Error("auto_update failed; keeping the loaded database",
				zap.String("db", kind.String()), zap.Error(err))
			continue
		}
		h.cur.Store(next)
		fetched[kind] = month
		a.metrics.downloads.WithLabelValues(kind.String(), "success").Inc()
		a.metrics.buildTime.WithLabelValues(kind.String()).Set(float64(next.built.Unix()))
		a.logDownload(kind, h.path, next)
	}
}

func (a *App) reloadLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	failed := make(map[string]reloadFailure)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.reloadOnce(failed)
		}
	}
}

// A version that failed to load is remembered so it is not retried, and the
// error not logged again, on every tick until the file changes.
type reloadFailure struct {
	statErr string
	stat    os.FileInfo
}

func (a *App) reloadOnce(failed map[string]reloadFailure) {
	a.mu.Lock()
	dbs := []*dbHolder{a.country, a.asn}
	lists := make([]*ipList, 0, len(a.ipLists))
	for _, l := range a.ipLists {
		lists = append(lists, l)
	}
	a.mu.Unlock()

	for _, h := range dbs {
		if h == nil {
			continue
		}
		key := "db:" + h.path
		cur := h.cur.Load()
		if !a.shouldReload(key, h.kind.String(), h.path, cur.stat, failed) {
			continue
		}
		next, err := loadDB(h.kind, h.path)
		if err != nil {
			a.reloadFailed(key, h.kind.String(), h.path, err, failed)
			continue
		}
		h.cur.Store(next)
		delete(failed, key)
		a.metrics.reloads.WithLabelValues(h.kind.String(), "success").Inc()
		a.metrics.buildTime.WithLabelValues(h.kind.String()).Set(float64(next.built.Unix()))
		a.logger.Info("reloaded database",
			zap.String("db", h.kind.String()),
			zap.String("path", h.path),
			zap.String("type", next.dbType),
			zap.Time("built", next.built))
	}

	for _, l := range lists {
		key := "ip_file:" + l.path
		cur := l.cur.Load()
		if !a.shouldReload(key, "ip_file", l.path, cur.stat, failed) {
			continue
		}
		next, err := loadIPList(l.path)
		if err != nil {
			a.reloadFailed(key, "ip_file", l.path, err, failed)
			continue
		}
		l.cur.Store(next)
		delete(failed, key)
		a.metrics.reloads.WithLabelValues("ip_file", "success").Inc()
		a.logger.Info("reloaded ip_file", zap.String("path", l.path), zap.Int("entries", next.count))
	}
}

func (a *App) shouldReload(key, db, path string, loaded os.FileInfo, failed map[string]reloadFailure) bool {
	st, err := os.Stat(path)
	if err != nil {
		if f, ok := failed[key]; ok && f.statErr == err.Error() {
			return false
		}
		failed[key] = reloadFailure{statErr: err.Error()}
		a.metrics.reloads.WithLabelValues(db, "error").Inc()
		a.logger.Error("cannot check file for changes; keeping the loaded data",
			zap.String("db", db), zap.String("path", path), zap.Error(err))
		return false
	}
	if !fileChanged(loaded, st) {
		delete(failed, key)
		return false
	}
	if f, ok := failed[key]; ok && f.stat != nil && !fileChanged(f.stat, st) {
		return false
	}
	return true
}

func (a *App) reloadFailed(key, db, path string, err error, failed map[string]reloadFailure) {
	f := reloadFailure{}
	if st, serr := os.Stat(path); serr == nil {
		f.stat = st
	}
	failed[key] = f
	a.metrics.reloads.WithLabelValues(db, "error").Inc()
	a.logger.Error("reload failed; keeping the previously loaded data",
		zap.String("db", db), zap.String("path", path), zap.Error(err))
}

var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
)
