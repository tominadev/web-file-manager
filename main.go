package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const maxUploadSize = 100 << 20

type User struct {
	Username       string `json:"username"`
	PasswordHash   string `json:"password_hash"`
	PrivateKeyData string `json:"private_key_data"`
	PublicKeyPEM   string `json:"public_key_pem"`
	IsAdmin        bool   `json:"is_admin"`
}
type FileMeta struct {
	ID           string    `json:"id"`
	Owner        string    `json:"owner"`
	OriginalName string    `json:"original_name"`
	StoredName   string    `json:"stored_name"`
	Size         int64     `json:"size"`
	UploadedAt   time.Time `json:"uploaded_at"`
}
type database struct {
	Users map[string]User     `json:"users"`
	Files map[string]FileMeta `json:"files"`
}
type app struct {
	mu                 sync.RWMutex
	data               database
	dataPath, filesDir string
	master             []byte
	sessions           map[string]string
}

var page = template.Must(template.New("page").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}} - Web File Manager</title><style>
body{font-family:system-ui,-apple-system,sans-serif;background:#f5f7fb;color:#172033;margin:0}.wrap{max-width:920px;margin:40px auto;padding:0 20px}.card{background:#fff;border:1px solid #e5e9f2;border-radius:12px;padding:24px;box-shadow:0 6px 20px #1720330a}h1{margin-top:0}.top{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:20px}a,button{color:#175cd3}button,.button{display:inline-block;border:0;border-radius:7px;background:#175cd3;color:#fff;padding:10px 15px;cursor:pointer;text-decoration:none;font-size:14px}input{width:100%;box-sizing:border-box;padding:10px;margin:7px 0 15px;border:1px solid #cbd5e1;border-radius:7px}label{font-weight:600;font-size:14px}table{width:100%;border-collapse:collapse}td,th{padding:12px 8px;border-bottom:1px solid #edf0f5;text-align:left}small,.muted{color:#667085}.error{background:#fff1f0;color:#b42318;padding:10px;border-radius:7px;margin-bottom:15px}.actions{white-space:nowrap}@media(max-width:650px){.top{align-items:flex-start;flex-direction:column}table{font-size:13px}.hide-mobile{display:none}}
</style></head><body><main class="wrap">{{template "content" .}}</main></body></html>`))

func init() {
	page = template.Must(page.Parse(`{{define "content"}}{{if .User}}<div class="top"><div><h1>File Manager</h1><div class="muted">Signed in as {{.User}}</div></div><form method="post" action="/logout"><button type="submit">Sign out</button></form></div><section class="card"><h2>Upload file</h2><form method="post" action="/upload" enctype="multipart/form-data"><input type="file" name="file" required><button type="submit">Encrypt and upload</button><p class="muted">Maximum file size: 100 MB. Files are encrypted before they are written to disk.</p></form></section><section class="card" style="margin-top:20px"><h2>My files</h2>{{if .Files}}<table><tr><th>Filename</th><th class="hide-mobile">Size</th><th class="hide-mobile">Uploaded</th><th>Actions</th></tr>{{range .Files}}<tr><td>{{.OriginalName}}</td><td class="hide-mobile">{{.Size}} bytes</td><td class="hide-mobile">{{.UploadedAt.Format "2006-01-02 15:04"}}</td><td class="actions"><a class="button" href="/download?id={{.ID}}">Download</a> <form style="display:inline" method="post" action="/delete?id={{.ID}}"><button type="submit" style="background:#b42318">Delete</button></form></td></tr>{{end}}</table>{{else}}<p class="muted">No files yet.</p>{{end}}</section>{{else}}<div class="card" style="max-width:420px;margin:80px auto"><h1>{{.Heading}}</h1>{{if .Error}}<div class="error">{{.Error}}</div>{{end}}{{if eq .Page "login"}}<form method="post" action="/login"><label>Username</label><input name="username" required autofocus><label>Password</label><input name="password" type="password" required><button type="submit">Sign in</button></form><p class="muted">No account yet? <a href="/register">Create one</a></p>{{else}}<form method="post" action="/register"><label>Username</label><input name="username" pattern="[A-Za-z0-9_-]{3,32}" required autofocus><label>Password</label><input name="password" type="password" minlength="8" required><button type="submit">Register</button></form><p class="muted">Already have an account? <a href="/login">Sign in</a></p>{{end}}</div>{{end}}{{end}}`))
}

var passwordPage = template.Must(template.New("password").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Change password - Web File Manager</title><style>body{font-family:system-ui,sans-serif;background:#f5f7fb;color:#172033}.card{max-width:420px;margin:80px auto;background:#fff;border:1px solid #e5e9f2;border-radius:12px;padding:24px}input{width:100%;box-sizing:border-box;padding:10px;margin:7px 0 15px;border:1px solid #cbd5e1;border-radius:7px}button,.button{border:0;border-radius:7px;background:#175cd3;color:#fff;padding:10px 15px;cursor:pointer;text-decoration:none}.error{background:#fff1f0;color:#b42318;padding:10px;border-radius:7px;margin-bottom:15px}.muted{color:#667085}</style></head><body><section class="card"><h1>Change password</h1><p class="muted">Signed in as {{.User}}</p>{{if .Error}}<div class="error">{{.Error}}</div>{{end}}<form method="post" action="/change-password"><label>Current password</label><input type="password" name="current_password" required autofocus><label>New password</label><input type="password" name="new_password" minlength="8" required><label>Confirm new password</label><input type="password" name="confirm_password" minlength="8" required><button type="submit">Change password</button></form><p><a href="/">Back to files</a></p></section></body></html>`))

var adminPage = template.Must(template.New("admin").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin - Web File Manager</title><style>body{font-family:system-ui,sans-serif;background:#f5f7fb;color:#172033;margin:0}.wrap{max-width:1100px;margin:40px auto;padding:0 20px}.card{background:#fff;border:1px solid #e5e9f2;border-radius:12px;padding:24px;margin-bottom:20px}table{width:100%;border-collapse:collapse}td,th{padding:10px 8px;border-bottom:1px solid #edf0f5;text-align:left}button,.button{border:0;border-radius:7px;background:#175cd3;color:#fff;padding:8px 12px;cursor:pointer;text-decoration:none}.danger{background:#b42318}a{color:#175cd3}.muted{color:#667085}</style></head><body><main class="wrap"><p><a href="/">My files</a> · <a href="/change-password">Change password</a></p><h1>Admin dashboard</h1><div class="card"><h2>Overview</h2><p><strong>{{.UserCount}}</strong> users · <strong>{{.FileCount}}</strong> files · <strong>{{.TotalBytes}}</strong> bytes stored</p></div><div class="card"><h2>Users</h2><table><tr><th>Username</th><th>Role</th></tr>{{range .Users}}<tr><td>{{.Username}}</td><td>{{if .IsAdmin}}Administrator{{else}}User{{end}}</td></tr>{{end}}</table></div><div class="card"><h2>All files</h2>{{if .Files}}<table><tr><th>Filename</th><th>Owner</th><th>Size</th><th>Uploaded</th><th>Actions</th></tr>{{range .Files}}<tr><td>{{.OriginalName}}</td><td>{{.Owner}}</td><td>{{.Size}} bytes</td><td>{{.UploadedAt.Format "2006-01-02 15:04"}}</td><td><a class="button" href="/download?id={{.ID}}">Download</a> <form style="display:inline" method="post" action="/admin/delete-file?id={{.ID}}"><button class="danger" type="submit">Delete</button></form></td></tr>{{end}}</table>{{else}}<p class="muted">No files uploaded.</p>{{end}}</div></main></body></html>`))

var modernPage = template.Must(template.New("modern-page").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}} · Web File Manager</title><style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#172033;background:#f4f7fb}*{box-sizing:border-box}body{margin:0}.shell{max-width:1080px;margin:0 auto;padding:28px 20px}.nav{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:30px}.brand{font-size:20px;font-weight:750;color:#172033;text-decoration:none}.nav-right{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.nav a{color:#475467;text-decoration:none}.nav a:hover{color:#175cd3}.role{display:inline-flex;padding:5px 9px;border-radius:999px;background:#eaf2ff;color:#175cd3;font-size:12px;font-weight:700}.button,button{border:0;border-radius:8px;background:#175cd3;color:#fff;padding:10px 14px;font:inherit;font-size:14px;cursor:pointer;text-decoration:none;display:inline-block}.button.secondary{background:#eef2f7;color:#344054}.button.danger{background:#b42318}.hero{display:flex;justify-content:space-between;align-items:end;gap:20px;margin-bottom:22px}.eyebrow{color:#667085;font-size:14px;margin:0 0 6px}.hero h1{font-size:32px;letter-spacing:-.03em;margin:0}.card{background:#fff;border:1px solid #e4eaf2;border-radius:16px;padding:24px;box-shadow:0 10px 24px rgba(16,24,40,.04);margin-bottom:20px}.card h2{font-size:18px;margin:0 0 8px}.muted{color:#667085;font-size:14px}.upload{display:flex;justify-content:space-between;align-items:center;gap:18px}.upload input{max-width:440px;width:100%;padding:10px;border:1px solid #cbd5e1;border-radius:8px;background:#fff}table{width:100%;border-collapse:collapse}td,th{padding:14px 8px;border-bottom:1px solid #edf0f5;text-align:left;font-size:14px}th{color:#667085;font-weight:600}.actions{white-space:nowrap}.empty{text-align:center;padding:28px 10px}.auth{max-width:440px;margin:9vh auto}.auth h1{margin:0 0 8px;font-size:28px}.field{margin:18px 0}.field label{display:block;font-size:14px;font-weight:650;margin-bottom:7px}.field input{width:100%;padding:12px;border:1px solid #cbd5e1;border-radius:8px;font:inherit}.error{padding:11px 13px;border-radius:8px;background:#fff1f0;color:#b42318;margin:16px 0;font-size:14px}.auth-footer{margin-top:18px;font-size:14px;color:#667085}.auth-footer a{color:#175cd3}@media(max-width:680px){.shell{padding:20px 14px}.nav,.hero,.upload{align-items:flex-start;flex-direction:column}.hero h1{font-size:27px}.hide-mobile{display:none}.card{padding:18px}.actions .button{padding:8px 10px}}
</style></head><body><main class="shell">{{if .User}}<nav class="nav"><a class="brand" href="/">Web File Manager</a><div class="nav-right"><span class="muted">{{.User}}</span><span class="role">{{if .IsAdmin}}Administrator{{else}}User{{end}}</span><a href="/change-password">Change password</a>{{if .IsAdmin}}<a class="button secondary" href="/admin">Admin</a>{{end}}<form method="post" action="/logout"><button class="button secondary" type="submit">Sign out</button></form></div></nav><div class="hero"><div><p class="eyebrow">Secure personal storage</p><h1>My files</h1></div></div><section class="card upload"><div><h2>Upload a file</h2><p class="muted">Files are encrypted before they are written to disk. Maximum size: 100 MB.</p></div><form method="post" action="/upload" enctype="multipart/form-data"><input type="file" name="file" required><button type="submit">Encrypt and upload</button></form></section><section class="card"><h2>Your files</h2>{{if .Files}}<table><tr><th>Filename</th><th class="hide-mobile">Size</th><th class="hide-mobile">Uploaded</th><th>Actions</th></tr>{{range .Files}}<tr><td>{{.OriginalName}}</td><td class="hide-mobile">{{.Size}} bytes</td><td class="hide-mobile">{{.UploadedAt.Format "2006-01-02 15:04"}}</td><td class="actions"><a class="button" href="/download?id={{.ID}}">Download</a> <form style="display:inline" method="post" action="/delete?id={{.ID}}"><button class="button danger" type="submit">Delete</button></form></td></tr>{{end}}</table>{{else}}<div class="empty"><p class="muted">No files yet.</p><a href="#upload">Upload your first file</a></div>{{end}}</section>{{else}}<section class="card auth"><a class="brand" href="/">Web File Manager</a><h1>{{.Heading}}</h1><p class="muted">Private, encrypted file storage.</p>{{if .Error}}<div class="error">{{.Error}}</div>{{end}}{{if eq .Page "login"}}<form method="post" action="/login"><div class="field"><label>Username</label><input name="username" required autofocus></div><div class="field"><label>Password</label><input name="password" type="password" required></div><button type="submit">Sign in</button></form><p class="auth-footer">No account yet? <a href="/register">Create one</a></p>{{else}}<form method="post" action="/register"><div class="field"><label>Username</label><input name="username" pattern="[A-Za-z0-9_-]{3,32}" required autofocus></div><div class="field"><label>Password</label><input name="password" type="password" minlength="8" required></div><button type="submit">Register</button></form><p class="auth-footer">Already have an account? <a href="/login">Sign in</a></p>{{end}}</section>{{end}}</main></body></html>`))

var modernAdminPage = template.Must(template.New("modern-admin").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin · Web File Manager</title><style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#172033;background:#f4f7fb}*{box-sizing:border-box}body{margin:0}.shell{max-width:1000px;margin:0 auto;padding:28px 20px}.nav{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:30px}.brand{font-size:20px;font-weight:750;color:#172033;text-decoration:none}.nav-right{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.nav a{color:#475467;text-decoration:none}.button,button{border:0;border-radius:8px;background:#175cd3;color:#fff;padding:10px 14px;font:inherit;font-size:14px;cursor:pointer;text-decoration:none}.button.secondary{background:#eef2f7;color:#344054}.card{background:#fff;border:1px solid #e4eaf2;border-radius:16px;padding:24px;box-shadow:0 10px 24px rgba(16,24,40,.04);margin-bottom:20px}.card h1{margin:0 0 8px}.card h2{font-size:18px;margin:0 0 16px}.muted{color:#667085;font-size:14px}.stats{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.stat{padding:18px;border:1px solid #e4eaf2;border-radius:12px}.stat strong{display:block;font-size:28px;margin-bottom:4px}table{width:100%;border-collapse:collapse}td,th{padding:14px 8px;border-bottom:1px solid #edf0f5;text-align:left;font-size:14px}th{color:#667085;font-weight:600}.role{display:inline-flex;padding:5px 9px;border-radius:999px;background:#eaf2ff;color:#175cd3;font-size:12px;font-weight:700}@media(max-width:680px){.shell{padding:20px 14px}.nav{align-items:flex-start;flex-direction:column}.card{padding:18px}.stats{grid-template-columns:1fr}}
</style></head><body><main class="shell"><nav class="nav"><a class="brand" href="/">Web File Manager</a><div class="nav-right"><a href="/">My files</a><a href="/change-password">Change password</a><form method="post" action="/logout"><button class="button secondary" type="submit">Sign out</button></form></div></nav><section class="card"><p class="muted">Administrator area</p><h1>User management</h1><p class="muted">Manage account visibility and roles. File contents remain a private user function.</p></section><section class="card"><h2>Overview</h2><div class="stats"><div class="stat"><strong>{{.UserCount}}</strong><span class="muted">Registered users</span></div><div class="stat"><strong>{{.AdminCount}}</strong><span class="muted">Administrators</span></div></div></section><section class="card"><h2>Users</h2><table><tr><th>Username</th><th>Role</th><th>Status</th></tr>{{range .Users}}<tr><td>{{.Username}}</td><td>{{if .IsAdmin}}<span class="role">Administrator</span>{{else}}User{{end}}</td><td>Active</td></tr>{{end}}</table></section></main></body></html>`))

func main() {
	root := env("WFM_DATA_DIR", "./data")
	master, err := loadMasterKey(root)
	if err != nil {
		log.Fatal(err)
	}
	a := &app{dataPath: filepath.Join(root, "db.json"), filesDir: filepath.Join(root, "files"), master: master, sessions: make(map[string]string)}
	if err := a.load(); err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(a.filesDir, 0700); err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.home)
	mux.HandleFunc("/login", a.login)
	mux.HandleFunc("/register", a.register)
	mux.HandleFunc("/change-password", a.changePassword)
	mux.HandleFunc("/logout", a.logout)
	mux.HandleFunc("/upload", a.upload)
	mux.HandleFunc("/download", a.download)
	mux.HandleFunc("/delete", a.delete)
	mux.HandleFunc("/admin", a.admin)
	mux.HandleFunc("/admin/reset-password", a.adminResetPassword)
	server := &http.Server{Addr: env("WFM_ADDR", ":8080"), Handler: securityHeaders(mux), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute}
	log.Printf("web file manager listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func loadMasterKey(root string) ([]byte, error) {
	if raw := os.Getenv("WFM_MASTER_KEY"); raw != "" {
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(key) != 32 {
			return nil, errors.New("WFM_MASTER_KEY must be a base64 encoded 32-byte key")
		}
		return key, nil
	}
	path := filepath.Join(root, ".master.key")
	if key, err := os.ReadFile(path); err == nil {
		if len(key) != 32 {
			return nil, errors.New("data/.master.key has an invalid length")
		}
		return key, nil
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		return nil, err
	}
	log.Printf("generated development master key at %s; set WFM_MASTER_KEY in production", path)
	return key, nil
}

func (a *app) load() error {
	raw, err := os.ReadFile(a.dataPath)
	if errors.Is(err, os.ErrNotExist) {
		a.data = database{Users: map[string]User{}, Files: map[string]FileMeta{}}
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &a.data); err != nil {
		return err
	}
	if a.data.Users == nil {
		a.data.Users = map[string]User{}
	}
	if a.data.Files == nil {
		a.data.Files = map[string]FileMeta{}
	}
	return nil
}
func (a *app) saveLocked() error {
	raw, err := json.MarshalIndent(a.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := a.dataPath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, a.dataPath)
}
func (a *app) render(w http.ResponseWriter, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := modernPageWithProgress.Execute(w, data); err != nil {
		http.Error(w, "template error", 500)
	}
}
func (a *app) currentUser(r *http.Request) string {
	c, err := r.Cookie("wfm_session")
	if err != nil {
		return ""
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.sessions[c.Value]
}
func (a *app) requireUser(w http.ResponseWriter, r *http.Request) string {
	if user := a.currentUser(r); user != "" {
		return user
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
	return ""
}

func (a *app) requireAdmin(w http.ResponseWriter, r *http.Request) string {
	user := a.requireUser(w, r)
	if user == "" {
		return ""
	}
	a.mu.RLock()
	admin := a.data.Users[user].IsAdmin
	a.mu.RUnlock()
	if !admin {
		http.Error(w, "administrator access required", http.StatusForbidden)
		return ""
	}
	return user
}

func (a *app) changePassword(w http.ResponseWriter, r *http.Request) {
	user := a.requireUser(w, r)
	if user == "" {
		return
	}
	if r.Method == http.MethodGet {
		a.renderPassword(w, user, "")
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	current := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")
	a.mu.RLock()
	account := a.data.Users[user]
	a.mu.RUnlock()
	if bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(current)) != nil {
		a.renderPassword(w, user, "Current password is incorrect")
		return
	}
	if len(newPassword) < 8 {
		a.renderPassword(w, user, "New password must be at least 8 characters")
		return
	}
	if newPassword != confirm {
		a.renderPassword(w, user, "New passwords do not match")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "password processing failed", http.StatusInternalServerError)
		return
	}
	a.mu.Lock()
	account.PasswordHash = string(hash)
	a.data.Users[user] = account
	err = a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		http.Error(w, "password save failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *app) renderPassword(w http.ResponseWriter, user, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	a.mu.RLock()
	isAdmin := a.data.Users[user].IsAdmin
	a.mu.RUnlock()
	if err := modernPasswordPage.Execute(w, map[string]any{"User": user, "IsAdmin": isAdmin, "Error": message}); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (a *app) admin(w http.ResponseWriter, r *http.Request) {
	user := a.requireAdmin(w, r)
	if user == "" {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.mu.RLock()
	users := make([]User, 0, len(a.data.Users))
	adminCount := 0
	for _, account := range a.data.Users {
		users = append(users, account)
		if account.IsAdmin {
			adminCount++
		}
	}
	a.mu.RUnlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := map[string]any{"UserCount": len(users), "AdminCount": adminCount, "Users": users}
	if err := modernAdminPageWithReset.Execute(w, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (a *app) adminResetPassword(w http.ResponseWriter, r *http.Request) {
	admin := a.requireAdmin(w, r)
	if admin == "" {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	target := strings.TrimSpace(r.FormValue("username"))
	newPassword := r.FormValue("new_password")
	if len(newPassword) < 8 {
		http.Error(w, "new password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "password processing failed", http.StatusInternalServerError)
		return
	}
	a.mu.Lock()
	account, ok := a.data.Users[target]
	if !ok {
		a.mu.Unlock()
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	account.PasswordHash = string(hash)
	a.data.Users[target] = account
	for token, sessionUser := range a.sessions {
		if sessionUser == target {
			delete(a.sessions, token)
		}
	}
	err = a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		http.Error(w, "password save failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (a *app) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	user := a.currentUser(r)
	if user == "" {
		a.render(w, map[string]any{"Title": "Sign in", "Heading": "Web File Manager", "Page": "login"})
		return
	}
	a.mu.RLock()
	account := a.data.Users[user]
	files := []FileMeta{}
	for _, f := range a.data.Files {
		if f.Owner == user {
			files = append(files, f)
		}
	}
	a.mu.RUnlock()
	a.render(w, map[string]any{"Title": "My files", "User": user, "IsAdmin": account.IsAdmin, "Files": files})
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.render(w, map[string]any{"Title": "Sign in", "Heading": "Web File Manager", "Page": "login"})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	a.mu.RLock()
	user, ok := a.data.Users[username]
	a.mu.RUnlock()
	if !ok || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		a.render(w, map[string]any{"Title": "Sign in", "Heading": "Web File Manager", "Page": "login", "Error": "Invalid username or password"})
		return
	}
	a.startSession(w, username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *app) register(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.render(w, map[string]any{"Title": "Register", "Heading": "Create an account", "Page": "register"})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if len(username) < 3 || len(username) > 32 || len(password) < 8 || strings.ContainsAny(username, `/\\`) {
		a.render(w, map[string]any{"Title": "Register", "Heading": "Create an account", "Page": "register", "Error": "Username must be 3-32 characters and password must be at least 8 characters"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "password processing failed", 500)
		return
	}
	private, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		http.Error(w, "key generation failed", 500)
		return
	}
	privatePEM, err := marshalPrivate(private)
	if err != nil {
		http.Error(w, "key generation failed", 500)
		return
	}
	privateData, err := encryptBlob(a.master, privatePEM)
	if err != nil {
		http.Error(w, "key encryption failed", 500)
		return
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&private.PublicKey)})
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.data.Users[username]; exists {
		a.render(w, map[string]any{"Title": "Register", "Heading": "Create an account", "Page": "register", "Error": "Username already exists"})
		return
	}
	a.data.Users[username] = User{Username: username, PasswordHash: string(hash), PrivateKeyData: base64.StdEncoding.EncodeToString(privateData), PublicKeyPEM: string(publicPEM), IsAdmin: len(a.data.Users) == 0}
	if err := a.saveLocked(); err != nil {
		http.Error(w, "account save failed", 500)
		return
	}
	a.startSessionLocked(w, username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func marshalPrivate(k *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
func (a *app) startSession(w http.ResponseWriter, user string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.startSessionLocked(w, user)
}
func (a *app) startSessionLocked(w http.ResponseWriter, user string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	a.sessions[token] = user
	http.SetCookie(w, &http.Cookie{Name: "wfm_session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 86400})
}
func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if c, err := r.Cookie("wfm_session"); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "wfm_session", Path: "/", MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *app) upload(w http.ResponseWriter, r *http.Request) {
	user := a.requireUser(w, r)
	if user == "" {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize+1<<20)
	if err := r.ParseMultipartForm(maxUploadSize + 1<<20); err != nil {
		http.Error(w, "file is too large; maximum is 100 MB", 413)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "choose a file", 400)
		return
	}
	defer file.Close()
	plain, err := io.ReadAll(io.LimitReader(file, maxUploadSize+1))
	if err != nil || int64(len(plain)) > maxUploadSize {
		http.Error(w, "file is too large; maximum is 100 MB", 413)
		return
	}
	a.mu.RLock()
	owner := a.data.Users[user]
	a.mu.RUnlock()
	publicBlock, _ := pem.Decode([]byte(owner.PublicKeyPEM))
	if publicBlock == nil {
		http.Error(w, "user key is damaged", 500)
		return
	}
	pub, err := x509.ParsePKCS1PublicKey(publicBlock.Bytes)
	if err != nil {
		http.Error(w, "user key is damaged", 500)
		return
	}
	content, err := encryptFile(plain, pub)
	if err != nil {
		http.Error(w, "encryption failed", 500)
		return
	}
	idBytes := make([]byte, 16)
	_, _ = rand.Read(idBytes)
	id := hex.EncodeToString(idBytes)
	stored := filepath.Join(a.filesDir, id+".wfm")
	if err := os.WriteFile(stored, content, 0600); err != nil {
		http.Error(w, "file save failed", 500)
		return
	}
	meta := FileMeta{ID: id, Owner: user, OriginalName: filepath.Base(header.Filename), StoredName: stored, Size: int64(len(plain)), UploadedAt: time.Now().UTC()}
	a.mu.Lock()
	a.data.Files[id] = meta
	err = a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		_ = os.Remove(stored)
		http.Error(w, "metadata save failed", 500)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func encryptFile(plain []byte, pub *rsa.PublicKey) ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, plain, nil)
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, dek, nil)
	if err != nil {
		return nil, err
	}
	out := append([]byte("WFMv1\x00\x00\x00"), nonce...)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(wrapped)))
	out = append(out, n[:]...)
	out = append(out, wrapped...)
	out = append(out, sealed...)
	return out, nil
}

func (a *app) download(w http.ResponseWriter, r *http.Request) {
	user := a.requireUser(w, r)
	if user == "" {
		return
	}
	id := r.URL.Query().Get("id")
	a.mu.RLock()
	meta, ok := a.data.Files[id]
	a.mu.RUnlock()
	if !ok || meta.Owner != user {
		http.NotFound(w, r)
		return
	}
	a.mu.RLock()
	owner := a.data.Users[user]
	a.mu.RUnlock()
	encrypted, err := os.ReadFile(meta.StoredName)
	if err != nil {
		http.Error(w, "file not found", 404)
		return
	}
	privatePEM, err := base64.StdEncoding.DecodeString(owner.PrivateKeyData)
	if err != nil {
		http.Error(w, "user key is damaged", 500)
		return
	}
	rawPEM, err := decryptBlob(a.master, privatePEM)
	if err != nil {
		http.Error(w, "user key decryption failed", 500)
		return
	}
	block, _ := pem.Decode(rawPEM)
	if block == nil {
		http.Error(w, "private key is damaged", 500)
		return
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		http.Error(w, "private key is damaged", 500)
		return
	}
	private, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		http.Error(w, "private key type is invalid", 500)
		return
	}
	plain, err := decryptFile(encrypted, private)
	if err != nil {
		http.Error(w, "file decryption failed", 500)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", meta.OriginalName))
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, meta.OriginalName, meta.UploadedAt, strings.NewReader(string(plain)))
}
func decryptFile(data []byte, private *rsa.PrivateKey) ([]byte, error) {
	if len(data) < 24 || string(data[:8]) != "WFMv1\x00\x00\x00" {
		return nil, errors.New("invalid file format")
	}
	nonce := data[8:20]
	n := int(binary.BigEndian.Uint32(data[20:24]))
	if n <= 0 || 24+n > len(data) {
		return nil, errors.New("invalid key length")
	}
	dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, private, data[24:24+n], nil)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, data[24+n:], nil)
}
func (a *app) delete(w http.ResponseWriter, r *http.Request) {
	user := a.requireUser(w, r)
	if user == "" {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	id := r.URL.Query().Get("id")
	a.mu.Lock()
	meta, ok := a.data.Files[id]
	if ok && meta.Owner == user {
		delete(a.data.Files, id)
		_ = os.Remove(meta.StoredName)
		_ = a.saveLocked()
	}
	a.mu.Unlock()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func encryptBlob(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, gcm.Seal(nil, nonce, plain, nil)...), nil
}
func decryptBlob(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(data) < gcm.NonceSize() {
		return nil, errors.New("invalid encrypted blob")
	}
	return gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}
