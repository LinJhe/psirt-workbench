# PSIRT Workbench

**現有核心程式的去識別分享版**。這是一個供單人於 Linux／WSL 使用的產品安全工作台：將來源快照、案件進度、人工覆核與報告放在同一個可追溯流程中。

本套件附帶的資料全部是合成範例，不能當作公司現況、產品影響判定或真實漏洞通報。原工作台、公司資料與歷史紀錄仍保留在原本本機環境；這份複本沒有連向原本的資料目錄。

## 可以操作什麼？

| 模組 | 本版功能 |
|---|---|
| 案件流程與工時 | 登錄節點、承接、下一步、實際工時與成果；保存修訂歷程 |
| Salesforce 來信待辦 | 以郵件識別碼追蹤跨日待辦、規則分類、回答狀態與人工覆核 |
| Jira 進度 | 區分未結案、已完成與未知狀態，提供來源及後續處理線索 |
| KEV／DT 統計 | 區分不同 CVE、finding 與專案，查看元件版本及漏洞明細；命中不是受影響判定 |
| 報告 | 每輪產生 HTML、JSON、Daily、Weekly，保留來源時間、完整性與歷史批次 |
| 本機工作台 | 搜尋、篩選、來源證據、重要網址、SQLite 保存與備份 |

本版以確定性規則運作，沒有接入 LLM、Agent 或 Herdr。尚未提供多人協作、正式部署或企業權限管理。

## 開始使用

需要 **Python 3.11 以上、Linux 或既有 WSL**，以及可解析 `Asia/Taipei` 的系統時區資料。本機示範使用 Python 標準庫與 SQLite，不需要 Node build、不下載套件，也不需要公司帳號。

在解壓或 clone 後的專案資料夾，使用一般 Linux／Kali shell 執行：

```bash
python3 -B scripts/demo.py build
python3 -B scripts/demo.py start
```

第二條命令會輸出本次工作台的 localhost 網址；在瀏覽器開啟該網址。不要沿用另一部電腦或舊執行紀錄的埠號。

示範資料保存在 `runtime/demo/`。在工作頁保存人工紀錄後，重開同一個示範工作台可讀回；再次 `build` 會建立新報告批次，保留原批次及人工紀錄。這些動作不刷新公司來源。

停止本套件啟動的示範服務：

```bash
python3 -B scripts/demo.py stop
```

### Windows 入口

已有 Kali WSL 時，可在 Windows 檔案總管雙擊專案根目錄的 **`Launch-Demo.cmd`**。它會啟動這份複本的示範工作台，成功後開啟瀏覽器；初次使用會建立合成示範，已有資料時直接開啟。

預設 WSL 發行版為 `kali-linux`；可在 PowerShell 設定 `PSIRT_WSL_DISTRO`，或執行 `scripts/windows/Launch-Demo.ps1 -Distro <發行版名稱>`。啟動器不安裝 WSL、不內嵌憑證、不新增排程。

`-NoOpen -NoPause` 可用於驗收啟動結果而不開啟瀏覽器。Windows 實際啟動驗收狀態以本批交付證據為準，單有啟動檔不代表所有 Windows／WSL 版本皆已驗證。

## 最小驗收

```bash
python3 -B scripts/check.py
```

測試使用隔離合成資料。驗收重點是：

1. 同一 CVE 在兩個專案出現，計數為不同 CVE 1、findings 2、專案 2，不宣稱兩個產品。
2. 來源失敗或分頁不完整時顯示 Unknown／PARTIAL；完整成功零筆才顯示 0。
3. 同一快照重跑不重複累計，舊報告不覆寫。
4. 人工紀錄保存後可讀回，過期版本不能靜默覆蓋新修訂。
5. 規則建議、來源事實、人工覆核分開呈現。

本批實測 375 項通過，7 項未隨包企鵝素材測試略過。詳見 [驗收紀錄](docs/VALIDATION.md)。沒有宣稱正式 API 或所有瀏覽器已實測。

## 程式在哪裡？

```text
scripts/
  demo.py                   合成示範入口
  check.py                  隔離驗收入口
  run_psirt_ops.py           取數／快照重播／重建報告 CLI
  run_psirt_casework.py      localhost 工作台 CLI
  psirt_ops/                來源 adapter、統計、HTML／Daily／Weekly
  psirt_casework/           SQLite、案件、來信覆核、HTTP 與前端資產
  psirt_daily/              快照比較與離線防護
examples/                   合成輸入及報告設定
runtime/                    執行後產生；不納入版本庫
```

前端是原生 HTML／JavaScript／CSS，加上本機 Tailwind 樣式；後端是 Python `http.server` 與 SQLite，沒有 Flask、Django 或 React。完整資料流見 [架構說明](docs/ARCHITECTURE.md)。需要接入已授權來源時，先看 [整合設定與限制](docs/INTEGRATIONS.md)；示範入口不會啟用正式取數。

## 分享版與原環境的差異

- 保留工作流、保存、統計、報告與測試核心；原環境的公司主機、案件背景、產品對應與私人書籤不隨包。
- Weekly 改用範例格式；不能宣稱此範例是公司核准模板。
- 內部簡報、訓練案例、個人頭像與企鵝素材不隨包；庭院與字型的來源說明見 [第三方素材](THIRD_PARTY_NOTICES.md)。
- 外部來源設定由環境與範例設定提供，不搬移原本 `.env`、登入資訊或家目錄設定。
- 不包含原 Git 歷史、公司快照、郵件、SQLite、日誌、控制 token 或原網站的其他模組。

## 操作界線

本機 HTTP 服務只綁定 `127.0.0.1`。請勿直接暴露到網路或以本版替代多人正式系統；local token 與 Origin 檢查是本機防護，不是企業身分驗證。

本機「已完成」不代表正式案件結案；`RESOLVED`、`EXPLOITABLE`、KEV 命中與數量下降不能單獨證明修復、遭利用或風險解除。未確認的承接與期限保持待確認。正式安全判定、風險接受、發布及公司資料修改仍需權責者決定。

執行資料可能包含後續匯入的敏感內容，請勿將 `runtime/` 或 `.env` 加入 Git。現有 `.gitignore` 是防誤操作措施，不取代上傳前檢查。

## 授權狀態

本專案尚未指定開源授權；不能把私人儲存庫或可下載套件視為公開再散布授權。程式與自有內容之權利保留，第三方素材依各自授權處理，見 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
