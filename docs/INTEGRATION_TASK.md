# Complete Integration of HCEFHook Components for Observe Mode SENSF_RES Injection

## 背景 (Background)

PR #X で HCEFHook の主要コンポーネント (70%) が実装されましたが、コンポーネント間の接続 (30%) が未完成です。各コンポーネントは独立して機能しますが、統合されていないため、エンドツーエンドの SENSF_REQ 検出 → SENSF_RES 注入フローが動作しません。

## 実装済みコンポーネント

以下のコンポーネントが既に実装され、ビルド成功しています：

1. **ObserveModeManager** - Observe Mode の起動/SENSF_REQ 検出
2. **SprayController** - 連続 SENSF_RES 送信 (Spray Strategy)
3. **Native Hooks** - Symbol 解決と state discovery
4. **KernelSU Module** - Config オーバーレイ
5. **既存 Xposed Hooks** - PollingFrameHook, SendRawFrameHook, NfaStateHook

詳細は `docs/REMAINING_WORK.md` を参照してください。

## 必要な統合作業 (Integration Tasks)

### 🔴 CRITICAL (必須)

#### 1. PollingFrameHook → ObserveModeManager 接続

**ファイル**: `app/src/main/java/app/aoki/yuki/hcefhook/xposed/hooks/PollingFrameHook.java`

**変更内容**:
```java
private static void processPollingFrame(byte[] frameData, LogBroadcaster broadcaster) {
    broadcaster.debug("Processing polling frame: " + SensfResBuilder.toHexString(frameData));
    
    // ここに追加: ObserveModeManager に通知
    try {
        ObserveModeManager.onPollingFrameReceived(frameData);
        broadcaster.info("Polling frame forwarded to ObserveModeManager");
    } catch (Exception e) {
        broadcaster.error("Failed to forward to ObserveModeManager: " + e.getMessage());
    }
    
    // 既存のコールバック処理も維持
    if (callback != null) {
        // ...
    }
}
```

**検証方法**:
- ビルド成功確認
- logcat で "Polling frame forwarded to ObserveModeManager" を確認

#### 2. MainActivity → ObserveModeManager 統合

**ファイル**: `app/src/main/java/app/aoki/yuki/hcefhook/ui/MainActivity.java`

**変更内容**:

**A. onCreate() で初期化**:
```java
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);
    
    // 追加: ObserveModeManager 初期化
    boolean initialized = ObserveModeManager.initialize(this);
    if (initialized) {
        appendLog("INFO", "ObserveModeManager initialized");
        appendLog("INFO", ObserveModeManager.getStatus());
    } else {
        appendLog("ERROR", "ObserveModeManager initialization failed");
    }
    
    // 既存の初期化コード
    ipcClient = new IpcClient(this);
    initViews();
    // ...
}
```

**B. UI ボタンの追加 (res/layout/activity_main.xml)**:
```xml
<Button
    android:id="@+id/observeModeButton"
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    android:text="Toggle Observe Mode" />

<Button
    android:id="@+id/sprayModeButton"
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    android:text="Toggle Spray Mode" />
```

**C. ボタンハンドラの追加**:
```java
private void initViews() {
    // 既存のビューの初期化
    
    // 追加: Observe Mode ボタン
    Button observeModeBtn = findViewById(R.id.observeModeButton);
    observeModeBtn.setOnClickListener(v -> {
        if (ObserveModeManager.isObserveModeActive()) {
            ObserveModeManager.disableObserveMode();
            appendLog("INFO", "Observe Mode disabled");
        } else {
            boolean success = ObserveModeManager.enableObserveMode();
            if (success) {
                appendLog("INFO", "Observe Mode enabled");
                registerObserveModeCallback();
            } else {
                appendLog("ERROR", "Failed to enable Observe Mode");
            }
        }
    });
    
    // Spray Mode ボタンは autoInjectCheck の変更で SprayController を制御
}

private void registerObserveModeCallback() {
    ObserveModeManager.setSensfReqCallback((reqData, systemCode) -> {
        runOnUiThread(() -> {
            appendLog("DETECT", "SENSF_REQ detected: SC=0x" + 
                     String.format("%04X", systemCode));
            
            // Auto-inject が有効なら Spray Mode で応答
            if (autoInjectCheck != null && autoInjectCheck.isChecked()) {
                byte[] idm = hexToBytes(idmInput.getText().toString());
                byte[] pmm = hexToBytes(pmmInput.getText().toString());
                byte[] sensfRes = new SensfResBuilder()
                    .setIdm(idm)
                    .setPmm(pmm)
                    .build();
                
                // SprayController は Xposed process で動作するため、IPC 経由で起動
                appendLog("INFO", "Triggering spray mode injection...");
                ipcClient.triggerSprayInjection(sensfRes);
            }
        });
    });
}
```

**検証方法**:
- UI にボタンが表示されることを確認
- ボタン押下で Observe Mode が有効化されることを logcat で確認

#### 3. SendRawFrameHook → SprayController 接続

**ファイル**: `app/src/main/java/app/aoki/yuki/hcefhook/xposed/hooks/SendRawFrameHook.java`

**変更内容**:

**A. NativeNfcManager 参照を SprayController に渡す**:
```java
private static void cacheTransceiveMethod(Class<?> nativeNfcClass) {
    if (transceiveMethod != null) return;
    
    try {
        transceiveMethod = nativeNfcClass.getDeclaredMethod(
            "doTransceive", byte[].class, boolean.class, int[].class);
        transceiveMethod.setAccessible(true);
        XposedBridge.log(TAG + ": Cached doTransceive method");
        
        // 追加: SprayController に参照を渡す
        SprayController.setNativeNfcManager(nativeNfcManagerInstance, transceiveMethod);
        XposedBridge.log(TAG + ": NativeNfcManager configured for SprayController");
    } catch (NoSuchMethodException e) {
        XposedBridge.log(TAG + ": Could not cache doTransceive: " + e.getMessage());
    }
}
```

**B. Spray Mode での注入**:
```java
public static void injectSensfRes(byte[] sensfRes) {
    pendingInjection = sensfRes;
    injectionPending.set(true);
    XposedBridge.log(TAG + ": SENSF_RES queued for injection: " + 
        SensfResBuilder.toHexString(sensfRes));
    
    // 追加: Spray Mode が有効なら SprayController を使用
    if (DobbyHooks.isSprayModeEnabled()) {
        XposedBridge.log(TAG + ": Using SprayController for continuous transmission");
        SprayController.startSpray(sensfRes);
    } else {
        // 従来の single-shot injection
        attemptInjection();
    }
}
```

**検証方法**:
- logcat で "NativeNfcManager configured for SprayController" を確認
- Spray mode 有効時に連続送信ログを確認

### ⚠️ HIGH PRIORITY (推奨)

#### 4. 全レイヤーへのログ追加

以下のクラスに包括的なログを追加 (各メソッドの開始/終了、重要な状態変化):

- `app/src/main/java/app/aoki/yuki/hcefhook/core/Constants.java`
- `app/src/main/java/app/aoki/yuki/hcefhook/core/SensfResBuilder.java`
- `app/src/main/java/app/aoki/yuki/hcefhook/ipc/IpcClient.java`
- `app/src/main/java/app/aoki/yuki/hcefhook/ipc/HookIpcProvider.java`
- `app/src/main/java/app/aoki/yuki/hcefhook/core/LogReceiver.java`
- `app/src/main/java/app/aoki/yuki/hcefhook/xposed/ContextProvider.java`

**ログフォーマット例**:
```java
private static final String TAG = "HcefHook.ClassName";

public void methodName(Type param) {
    Log.d(TAG, "methodName() called with param=" + param);
    try {
        // 処理
        Log.d(TAG, "methodName() completed successfully");
    } catch (Exception e) {
        Log.e(TAG, "methodName() failed: " + e.getMessage(), e);
        throw e;
    }
}
```

#### 5. IpcClient に SprayController トリガーメソッド追加

**ファイル**: `app/src/main/java/app/aoki/yuki/hcefhook/ipc/IpcClient.java`

**追加メソッド**:
```java
/**
 * Trigger spray mode injection in Xposed hooks
 * 
 * @param sensfRes SENSF_RES frame to spray
 * @return true if trigger sent successfully
 */
public boolean triggerSprayInjection(byte[] sensfRes) {
    try {
        Uri uri = Uri.parse("content://" + AUTHORITY + "/spray_injection");
        ContentValues values = new ContentValues();
        values.put("sensf_res", sensfRes);
        values.put("timestamp", System.currentTimeMillis());
        
        Uri result = context.getContentResolver().insert(uri, values);
        return result != null;
    } catch (Exception e) {
        Log.e(TAG, "Failed to trigger spray injection: " + e.getMessage());
        return false;
    }
}
```

**対応する HookIpcProvider の追加**:
```java
@Override
public Uri insert(Uri uri, ContentValues values) {
    String path = uri.getPath();
    
    if ("/spray_injection".equals(path)) {
        byte[] sensfRes = values.getAsByteArray("sensf_res");
        if (sensfRes != null) {
            // SprayController.startSpray() を呼び出す
            // (Xposed process で実行される)
            SprayController.startSpray(sensfRes);
            return Uri.parse("content://" + AUTHORITY + "/spray_injection/success");
        }
    }
    
    // 既存の処理
    return super.insert(uri, values);
}
```

### 📝 MEDIUM PRIORITY (ドキュメント)

#### 6. README.md 更新

以下のセクションを追加:
- ObserveModeManager の使用方法
- SprayController の動作説明
- KernelSU module のインストール手順
- 統合アーキテクチャ図

#### 7. SECURITY_SUMMARY.md 作成

以下の内容を含むセキュリティサマリ:
- Root 権限要件
- KernelSU 使用のリスク
- SELinux への影響
- 責任ある使用のガイドライン
- 研究目的の明確化

## 検証手順 (Verification)

### ビルド検証
```bash
./gradlew clean
./gradlew assembleDebug  # 1st build
./gradlew clean
./gradlew assembleDebug  # 2nd build (Protocol 1: Double Success)
```

### ログ検証
```bash
adb logcat | grep "HcefHook"
```

以下のログシーケンスを確認:
1. "ObserveModeManager initialized"
2. "Observe Mode enabled"
3. "Polling frame forwarded to ObserveModeManager"
4. "SENSF_REQ detected: SC=0xFFFF"
5. "Using SprayController for continuous transmission"
6. "Transmission #1", "#2", "#3"... (spray mode)

### 実機テスト (オプション)

実際の FeliCa リーダーを使用して:
1. Observe Mode を有効化
2. リーダーを近づける
3. SENSF_REQ 検出を確認
4. SENSF_RES 送信を確認
5. リーダーが IDm を認識することを確認

## 成功基準 (Definition of Done)

- [ ] 3つの CRITICAL 統合が完了し、ビルドが成功する
- [ ] Protocol 1 (Double Success Build) を満たす
- [ ] logcat で完全なフローのログが確認できる
- [ ] docs/REMAINING_WORK.md のチェックリストが完了
- [ ] Protocol 2 (8-Step Ultrathink Ritual) の最終確認が完了

## 参考資料

- `docs/REMAINING_WORK.md` - 詳細な残作業リストと背景
- `docs/SYMBOL_ANALYSIS.md` - Native hook ターゲットの解析結果
- `docs/ULTRATHINK_RITUAL_LOG.md` - これまでの検証ログ
- PR #X - 実装済みコンポーネントの詳細

## 注意事項

- 各統合後に必ずビルドを確認すること
- ログを追加する際、センシティブ情報 (IDm/PMm の実際の値) をログに出力しないこと
- IPC 通信は MainActivity (app process) と Xposed hooks (android.nfc process) の2つのプロセス間で行われることに注意
- SprayController は android.nfc process で動作するため、MainActivity から直接呼び出すことはできない (IPC 経由)
